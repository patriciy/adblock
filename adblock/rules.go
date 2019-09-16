/*
Package implements a parser and a matcher for AdBlockPlus rules.

The syntax of AdBlockPlus rules is partially defined in
https://adblockplus.org/en/filter-cheatsheet and
https://adblockplus.org/en/filters.

To parse rules and build a matcher:

	matcher := adblock.NewMatcher()
	fp, err := os.Open("easylist.txt")
	...
	rules, err := adblock.ParseRules(fp)
	for _, rule := range rules {
		err = matcher.AddRule(rule, 0)
		...
	}

To match HTTP requests:

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	rq := adblock.Request{
		URL: r.URL.String(),
		Domain: host,
		// possibly fill OriginDomain from Referrer header
		// and ContentType from HTTP response Content-Type.
		Timeout: 200 * time.Millisecond,
	}
	matched, id, err := matcher.Match(rq)
	if err != nil {
		...
	}
	if matched {
		// Use the rule identifier to print which rules was matched
	}
*/
package adblock

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

const (
	Included = iota
	Excluded = iota
)

const (
	Exact        = iota // string to match
	Wildcard     = iota // *
	Separator    = iota // ^
	StartAnchor  = iota // |
	DomainAnchor = iota // ||

	Root      = iota
	Substring = iota // Wildcard + Exact
	Referer   = iota //for $referer
)

func getPartName(ruleType int) string {
	switch ruleType {
	case Exact:
		return "exact"
	case Wildcard:
		return "wildcard"
	case Separator:
		return "separator"
	case StartAnchor:
		return "startanchor"
	case DomainAnchor:
		return "domainanchor"
	case Root:
		return "Root"
	case Substring:
		return "substring"
	default:
		return "unknown"
	}
}

// RulePart is the base component of rules. It represents a single
// matching element, like an exact match, a wildcard, a domain anchor...
type RulePart struct {
	// Rule type, like Exact, Wildcard, etc.
	Type int8
	// Rule part string representation
	Value []byte
}

// Rule represents a complete adblockplus rule.
type Rule struct {
	// Exception is true for exclusion rules (prefixed with "@@")
	Exception bool
	// Parts is the sequence of RulePart matching URLs
	Parts []*RulePart
}

// ParseRule parses a single rule.
func ParseRule(s string) (*Rule, error) {
	if rulePartsCache == nil {
		rulePartsCache = make(map[string]*RulePart)
		rulePartsDomainAnchorCache = make(map[string]*RulePart)
	}

	r := Rule{}

	s = strings.TrimSpace(s)
	if len(s) == 0 || s[0] == '!' {
		// Empty or comment
		return nil, nil
	}
	if strings.Contains(s, "##") || strings.Contains(s, "#?#") {
		// Element selectors are not supported
		return nil, nil
	}
	if strings.HasPrefix(s, "@@") {
		r.Exception = true
		s = s[2:]
	}
	if strings.HasPrefix(s, "||") {
		key := "||"
		p, ok := rulePartsDomainAnchorCache[key]
		if !ok {
			p = &RulePart{Type: DomainAnchor, Value: []byte("||")}
			rulePartsDomainAnchorCache[key] = p
		}
		r.Parts = append(r.Parts, p)
		s = s[2:]
	}

	opts := ""
	if pos := strings.LastIndex(s, "$"); pos >= 0 {
		opts = s[pos:]
		s = s[:pos]
	}

	var p *RulePart
	for len(s) > 0 {
		pos := strings.IndexAny(s, "*^|")
		if pos < 0 {
			key := s
			ok := false
			p, ok = rulePartsCache[key]
			if !ok {
				p = &RulePart{Type: Exact, Value: []byte(s)}
				rulePartsCache[key] = p
			}
			r.Parts = append(r.Parts, p)
			break
		}
		if pos > 0 {
			key := s[:pos]
			ok := false
			p, ok = rulePartsCache[key]
			if !ok {
				p = &RulePart{Type: Exact, Value: []byte(s[:pos])}
				rulePartsCache[key] = p
			}
			r.Parts = append(r.Parts, p)
		}
		t := Wildcard
		switch s[pos] {
		case '*':
			t = Wildcard
		case '^':
			t = Separator
		case '|':
			t = StartAnchor
		}
		r.Parts = append(r.Parts, &RulePart{Type: int8(t), Value: []byte(s[pos : pos+1])})
		s = s[pos+1:]
	}

	if len(opts) > 0 {
		if pos := strings.Index(opts, "referer="); pos >= 0 {
			opts = opts[pos+len("referer="):]
			pos := strings.IndexAny(s, "$")
			v := opts
			if pos >= 0 {
				v = opts[:pos]
			}
			r.Parts = append(r.Parts, &RulePart{Type: int8(Referer), Value: []byte(v)})
		}
	}

	return &r, nil
}

// ParseRules returns the sequence of rules extracted from supplied reader
// content.
func ParseRules(r io.Reader) ([]*Rule, error) {
	rules := []*Rule{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		r, err := ParseRule(scanner.Text())
		if r == nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, scanner.Err()
}

// Request defines client request properties to be matched against a set
// of rules.
type Request struct {
	// URL is matched against rule parts. Mandatory.
	URL string
	// Domain is matched against optional domain or third-party rules
	Domain  string
	Referer string
	// ContentType is matched against optional content rules. This
	// information is often available only in client responses. Filters
	// may be applied twice, once at request time, once at response time.
	ContentType string
	// OriginDomain is matched against optional third-party rules.
	OriginDomain string

	// Timeout is the maximum amount of time a single matching can take.
	Timeout   time.Duration
	CheckFreq int

	// GenericBlock is true if rules not matching a specific domain are to be
	// ignored. If nil, the matcher will determine it internally based on
	// $GenericBlock options.
	GenericBlock *bool
}

func (rq *Request) HasGenericBlock() bool {
	return rq.GenericBlock != nil && *rq.GenericBlock
}

// RuleNode is the node structure of rule trees.
// Rule trees start with a Root node containing any number of non-Root
// RuleNodes.
type RuleNode struct {
	Type     int8
	Value    []byte
	Children []*RuleNode
}

// GetValue returns the node representation. It may differ from Value field
// for composite nodes like Sustring.
func (n *RuleNode) GetValue() string {
	v := n.Value
	if n.Type == Substring {
		v = make([]byte, 1+len(n.Value))
		v[0] = '*'
		copy(v[1:], n.Value)
	}
	return string(v)
}

var rulePartsCache map[string]*RulePart
var rulePartsDomainAnchorCache map[string]*RulePart

func ClearCaches() {
	rulePartsCache = make(map[string]*RulePart)
	rulePartsDomainAnchorCache = make(map[string]*RulePart)
	debug.FreeOSMemory()
}

func (n *RuleNode) AddRule(parts []*RulePart, id int) error {
	if len(parts) == 0 {
		return nil
	}

	// Looks for existing matching rule parts
	part := parts[0]
	if part.Type != Exact && part.Type != Wildcard && part.Type != Separator &&
		part.Type != DomainAnchor && part.Type != Substring && part.Type != Referer {
		return fmt.Errorf("unknown rule part type: %+v", part)
	}
	var child *RuleNode
	value := part.Value
	t := int8(part.Type)
	for _, c := range n.Children {
		// TODO: be smarter with ExactMatch
		if c.Type == t && bytes.Equal(c.Value, value) {
			child = c
			break
		}
	}

	created := false
	if child == nil {
		child = &RuleNode{
			Type:  t,
			Value: value,
		}
		created = true
	}

	err := child.AddRule(parts[1:], id)

	if err == nil && created {
		// Do not modify the tree when failing to insert a rule
		n.Children = append(n.Children, child)
	}

	return err
}

var (
	reSeparator = regexp.MustCompile(`^(?:[^\w\d_\-\.%]|$)`)
)

// matchContext is forwarded to matching functions which call Continue(). The
// current match duration is sampled and the call aborted if it exceeds a
// timeout.
// On failed calls, location is set to the node terminating the match and
// duration is updated to the original duration plus the time exceeding the
// deadline.
type matchContext struct {
	counter      int
	freq         int
	duration     time.Duration
	deadline     time.Time
	location     *RuleNode
	GenericBlock bool
	isDomainRule int
}

func (ctx *matchContext) Continue(n *RuleNode) bool {
	if ctx.freq <= 0 {
		return true
	}
	ctx.counter += 1
	if ctx.counter < ctx.freq {
		return true
	}
	ctx.counter = 0
	now := time.Now()
	stop := now.After(ctx.deadline)
	if stop {
		ctx.location = n
		ctx.duration += now.Sub(ctx.deadline)
	}
	return !stop
}

func (n *RuleNode) matchChildren(ctx *matchContext, url []byte, rq *Request) int {
	if !ctx.Continue(n) {
		return -1
	}

	if len(n.Children) == 0 && n.Type != Root {
		return -1
	}
	// } else if len(url) == 0 && len(n.Children) > 0 {
	// 	hasRefererChild := false
	// 	isTrailingWildCard := false
	// 	for _, c := range n.Children {
	// 		if c.Type == Referer {
	// 			hasRefererChild = true
	// 			break
	// 		}
	// 	}
	// 	if !hasRefererChild {
	// 		return 0
	// 	}
	// }

	// If there are children they have to match
	for _, c := range n.Children {
		ruleId := c.dispatch(ctx, url, rq)
		if ruleId < 0 {
			return ruleId
		}
	}
	return 0
}

func matchDomainAnchor(url []byte, expectedDomain []byte) ([]byte, bool) {
	s := url
	// Match https?://
	if !bytes.HasPrefix(s, []byte("http")) {
		return nil, false
	}
	s = s[4:]
	if len(s) > 0 && s[0] == byte('s') {
		s = s[1:]
	}
	if !bytes.HasPrefix(s, []byte("://")) {
		return nil, false
	}
	s = s[3:]

	// Extract host:port part
	domain := s
	slash := bytes.IndexByte(s, byte('/'))
	if slash < 0 {
		s = nil
	} else {
		domain = s[:slash]
		s = s[slash:]
	}

	// Strip port
Port:
	for i := len(domain); i > 0; i-- {
		c := domain[i-1]
		switch c {
		case byte('0'), byte('1'), byte('2'), byte('3'), byte('4'),
			byte('5'), byte('6'), byte('7'), byte('8'), byte('9'):
			// OK, port numbers
		case byte(':'):
			domain = domain[:i-1]
			break Port
		default:
			break Port
		}
	}
	// Exact match
	if bytes.Equal(expectedDomain, domain) ||
		// Or subdomain
		bytes.HasSuffix(domain, expectedDomain) &&
			len(domain) > len(expectedDomain) &&
			domain[len(domain)-len(expectedDomain)-1] == byte('.') {
		return s, true
	}
	return nil, false
}

func (n *RuleNode) dispatch(ctx *matchContext, url []byte, rq *Request) int {

	for {
		//fmt.Printf("matching '%s' with %s[%s][final:%v]\n",
		//	string(url), getPartName(n.Type), string(n.Value), n.Opts != nil)
		switch n.Type {
		case Exact:
			if !bytes.HasPrefix(url, n.Value) {
				return 0
			}
			url = url[len(n.Value):]
			return n.matchChildren(ctx, url, rq)
		case Separator:
			m := reSeparator.FindSubmatch(url)
			if m == nil {
				return 0
			}
			url = url[len(m[0]):]
			return n.matchChildren(ctx, url, rq)
		case Wildcard:
			if len(n.Children) == 0 {
				// Fast-path trailing wildcards
				return n.matchChildren(ctx, nil, rq)
			}
			if len(url) == 0 {
				return n.matchChildren(ctx, url, rq)
			}
			for i := 0; i < len(url); i++ {
				ruleId := n.matchChildren(ctx, url[i:], rq)
				if ruleId < 0 {
					return ruleId
				}
			}
		case DomainAnchor:
			remaining, ok := matchDomainAnchor(url, n.Value)
			if ok {
				ctx.isDomainRule += 1
				ruleId := n.matchChildren(ctx, remaining, rq)
				ctx.isDomainRule -= 1
				return ruleId
			}
		case Root:
			return n.matchChildren(ctx, url, rq)
		case Substring:
			for {
				if len(url) == 0 {
					break
				}
				pos := bytes.Index(url, n.Value)
				if pos < 0 {
					break
				}
				url = url[pos+len(n.Value):]
				ruleId := n.matchChildren(ctx, url, rq)
				if ruleId < 0 {
					return ruleId
				}
			}
		case Referer:
			referersString := n.GetValue()
			inverseMatch := false
			if referersString[0] == '~' {
				referersString = referersString[1:]
				inverseMatch = true
			}

			if len(rq.Referer) == 0 {
				if inverseMatch {
					return -1
				}

				return 0
			}

			bytesReferer := []byte(rq.Referer)
			referers := strings.Split(referersString, "|")
			notMatched := true
			for _, referer := range referers {
				_, matched := matchDomainAnchor(bytesReferer, []byte(referer))
				if matched {
					if !inverseMatch {
						return -1
					}

					notMatched = false
				}
			}
			if notMatched && inverseMatch {
				return -1
			}
		}
		return 0
	}
}

// findNodePath returns the partial string represention of target and its
// ancestors in n subtree.
func findNodePath(target *RuleNode, n *RuleNode) (string, bool) {
	if target == n {
		return n.GetValue(), true
	}
	for _, c := range n.Children {
		s, ok := findNodePath(target, c)
		if ok {
			return n.GetValue() + s, true
		}
	}
	return "", false
}

type InterruptedError struct {
	Duration time.Duration
	Rule     string
}

func (e *InterruptedError) Error() string {
	return fmt.Sprintf("interrupted at %s after %.3s", e.Rule, e.Duration)
}

// Match evaluates a piece of a request URL against the node subtree. If it
// matches an existing rule, returns the rule identifier and its options set.
// Requests are evaluated by applying the nodes on its URL in DFS order. When
// the URL is completely matched by a terminal node, a node with a non-empty
// Opts set, the Opts are applied on the Request properties.  Any option match
// validates the URL as a whole and the matching rule identifier is returned.
// If the request timeout is set and exceeded, InterruptedError is returned.
func (n *RuleNode) Match(url []byte, rq *Request) (int, error) {
	ctx := &matchContext{
		freq:         rq.CheckFreq,
		duration:     rq.Timeout,
		GenericBlock: rq.HasGenericBlock(),
	}
	if rq.Timeout > 0 {
		ctx.deadline = time.Now().Add(rq.Timeout)
		if ctx.freq == 0 {
			ctx.freq = 1000
		}
	}
	id := n.dispatch(ctx, url, rq)
	if ctx.location != nil {
		rule, ok := findNodePath(ctx.location, n)
		if !ok {
			panic("could not find node in rule tree")
		}
		return id, &InterruptedError{
			Duration: ctx.duration,
			Rule:     rule,
		}
	}
	return id, nil
}

// A RuleTree matches a set of adblockplus rules.
type RuleTree struct {
	Root *RuleNode
}

// NewRuleTree returns a new empty RuleTree.
func newRuleTree() *RuleTree {
	return &RuleTree{
		Root: &RuleNode{
			Type: Root,
		},
	}
}

func rewriteDomainAnchors(parts []*RulePart) ([]*RulePart, error) {
	hasAnchor := false
	rewritten := []*RulePart{}
	for i, part := range parts {
		if part.Type == DomainAnchor {
			// Check next part is an exact match
			if i != 0 {
				return nil, fmt.Errorf("invalid non-starting domain anchor")
			}
			if len(parts) < 2 || parts[1].Type != Exact {
				return nil, fmt.Errorf("domain anchor must be followed by exact match")
			}
			hasAnchor = true
		} else if part.Type == Exact && hasAnchor {
			// Extract the domain part of the following Exact part
			value := part.Value
			domain := []byte("")
			slash := bytes.Index(value, []byte("/"))
			if slash >= 0 {
				domain = value[:slash]
				value = value[slash:]
			} else {
				domain = value
				value = nil
			}
			// Set the domain to the preceding anchor
			key := string(domain)
			p, ok := rulePartsDomainAnchorCache[key]
			if !ok {
				p = &RulePart{Type: DomainAnchor, Value: domain}
				rulePartsDomainAnchorCache[key] = p
			}
			rewritten[len(rewritten)-1] = p

			if value != nil && len(value) > 0 {
				// Append remaining trailing Exact
				p, ok = rulePartsCache[string(value)]
				if !ok {
					p = &RulePart{
						Type:  Exact,
						Value: value,
					}
					rulePartsCache[string(value)] = p
				}

				rewritten = append(rewritten, p)
			}
			hasAnchor = false
			continue
		}
		rewritten = append(rewritten, part)
	}
	return rewritten, nil
}

var rulePartWildCard *RulePart

// Add explicit leading and trailing wildcards where they are implicitely
// required.
func addLeadingTrailingWildcards(parts []*RulePart) []*RulePart {
	if rulePartWildCard == nil {
		rulePartWildCard = &RulePart{
			Type: Wildcard,
		}
	}
	rewritten := []*RulePart{}
	for i, part := range parts {
		first := i == 0
		last := i == len(parts)-1
		if first {
			// Match every leading byte unless the rule starts with an anchor
			if part.Type != StartAnchor && part.Type != DomainAnchor {
				rewritten = append(rewritten, rulePartWildCard)
			}
		}

		if part.Type == StartAnchor {
			if !first && !last {
				// Anchors in the middle of the rules are not anchor but
				// literal "|"
				rewritten = append(rewritten,
					&RulePart{
						Type:  Exact,
						Value: []byte("|"),
					})
			}
		} else {
			rewritten = append(rewritten, part)
		}

		if last {
			// Match every trailing byte unless the rule ends with an anchor
			if part.Type != StartAnchor {
				rewritten = append(rewritten, rulePartWildCard)
			}
		}
	}
	return rewritten
}

// Rewrite Wildcard + Exact as a Substring
func replaceWildcardWithSubstring(parts []*RulePart) []*RulePart {
	rewritten := []*RulePart{}
	for i, part := range parts {
		if i == 0 || parts[i-1].Type != Wildcard {
			rewritten = append(rewritten, part)
			continue
		}
		if part.Type != Exact {
			rewritten = append(rewritten, part)
			continue
		}
		rewritten[len(rewritten)-1] = &RulePart{
			Type:  Substring,
			Value: part.Value,
		}
	}
	return rewritten
}

// AddRule add a rule and its identifier to the rule tree.
func (t *RuleTree) AddRule(rule *Rule, ruleId int) error {
	rewritten, err := rewriteDomainAnchors(rule.Parts)
	if err != nil {
		return err
	}
	rewritten = addLeadingTrailingWildcards(rewritten)
	rewritten = replaceWildcardWithSubstring(rewritten)

	if len(rewritten) == 0 {
		return nil
	}
	return t.Root.AddRule(rewritten, ruleId)
}

// Match evaluates the request. If it matches any rule, it returns the
// rule identifier and its options.
func (t *RuleTree) Match(rq *Request) (int, error) {
	return t.Root.Match([]byte(rq.URL), rq)
}

func (t *RuleTree) String() string {
	/*	w := &bytes.Buffer{}
		var printNode func(*RuleNode, int)
		printNode = func(n *RuleNode, level int) {
			w.WriteString(strings.Repeat(" ", level))
			w.WriteString(getPartName(n.Type))
			switch n.Type {
			case Exact, DomainAnchor:
				w.WriteString("[")
				w.WriteString(string(n.Value))
				w.WriteString("]")
			}
			if len(n.Opts) > 0 {
				for _, opt := range n.Opts {
					fmt.Fprintf(w, "[%s]", opt.Raw)
				}
			}
			w.WriteString("\n")
			for _, c := range n.Children {
				printNode(c, level+1)
			}
		}
		printNode(t.Root, 0)
		return w.String()*/
	return ""
}

// RuleMatcher implements a complete set of include and exclude AdblockPlus
// rules.
type RuleMatcher struct {
	Includes *RuleTree
	Excludes *RuleTree
}

// NewMatcher returns a new empty matcher.
func NewMatcher() *RuleMatcher {
	return &RuleMatcher{
		Includes: newRuleTree(),
		Excludes: newRuleTree(),
	}
}

// AddRule adds a rule to the matcher. Supplied rule identifier will be
// returned by Match().
func (m *RuleMatcher) AddRule(rule *Rule, ruleId int) error {
	var tree *RuleTree

	if rule.Exception {
		tree = m.Excludes
	} else {
		tree = m.Includes
	}
	return tree.AddRule(rule, ruleId)
}

// Match applies include and exclude rules on supplied request. If the
// request is accepted, it returns true and the matching rule group
func (m *RuleMatcher) Match(rq *Request) (bool, int, error) {
	inc := m.Includes
	exc := m.Excludes

	id, err := exc.Match(rq)
	if err != nil {
		return false, 0, err
	}
	if id != 0 {
		return true, Excluded, nil
	}

	id, err = inc.Match(rq)
	if err != nil {
		return false, 0, err
	}
	if id != 0 {
		return true, Included, nil
	}
	return false, 0, nil
}

// String returns a textual representation of the include and exclude rules,
// matching request with or without content.
func (m *RuleMatcher) String() string {
	return "" /*fmt.Sprintf("Includes:\n%s\nExcludes:\n%s\n"+
	"content-Includes:\n%s\ncontent-Excludes:\n%s\n",
	m.Includes, m.Excludes, m.ContentIncludes, m.ContentExcludes)*/
}

func loadRulesFromFile(m *RuleMatcher, path string) (int, error) {
	fp, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer fp.Close()
	parsed, err := ParseRules(fp)
	if err != nil {
		return 0, err
	}
	added := 0
	for _, rule := range parsed {
		err := m.AddRule(rule, 0)
		if err == nil {
			added += 1
		}
	}
	return added, nil
}

func NewMatcherFromFiles(paths ...string) (*RuleMatcher, int, error) {
	added := 0
	m := NewMatcher()
	for _, path := range paths {
		n, err := loadRulesFromFile(m, path)
		if err != nil {
			return nil, 0, err
		}
		added += n
	}
	return m, added, nil
}
