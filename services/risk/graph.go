// Package risk implements Module E: contextual risk scoring of findings and
// attack-path analysis over the resource relationship graph.
//
// The model is deliberately transparent and rule-based. Scores are a
// prioritisation aid, not a probability of compromise.
package risk

import (
	"encoding/json"
	"sort"
	"strings"
)

// Internet is the virtual entry node of every attack path.
const Internet = "internet"

// Node is one resource in the graph.
type Node struct {
	ID            string
	Type          string
	Environment   string
	Tags          map[string]string
	Configuration map[string]any
}

// Edge is a stored relationship (source -[type]-> target).
type Edge struct {
	Source, Type, Target string
}

// Hop is one step of an attack path.
type Hop struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Via    string `json:"via"`    // relationship or derived capability
	Reason string `json:"reason"` // why this step is possible
}

// Path is a route from the internet to a sensitive resource.
type Path struct {
	Target      string `json:"target"`
	TargetType  string `json:"target_type"`
	Sensitivity int    `json:"sensitivity"`
	Hops        []Hop  `json:"hops"`
}

// Privilege levels.
const (
	PrivNone   = 0
	PrivScoped = 40
	PrivAdmin  = 100
)

// Graph is an attacker-movement graph derived from resources and edges.
type Graph struct {
	Nodes     map[string]Node
	out       map[string][]Hop // movement edges
	privilege map[string]int   // per role/policy
	exposed   map[string]string
}

var dataStores = map[string]bool{"storage.bucket": true, "database.instance": true}

// BuildGraph derives movement edges with these semantics:
//
//	internet -> public load balancer, public bucket, public database
//	internet -> instance, when an attached security group is open to the internet
//	load balancer -routes_to-> instance
//	instance -assumes-> role;  instance -reads_from/writes_to-> data store
//	admin role -> every data store (a role with a full-admin policy)
//
// Structural relationships (member_of, encrypts, logs_to, depends_on) do not
// let an attacker move and are ignored.
func BuildGraph(nodes []Node, edges []Edge) *Graph {
	g := &Graph{Nodes: map[string]Node{}, out: map[string][]Hop{}, privilege: map[string]int{}, exposed: map[string]string{}}
	for _, n := range nodes {
		g.Nodes[n.ID] = n
	}
	add := func(h Hop) { g.out[h.From] = append(g.out[h.From], h) }

	// Policy privilege, then role privilege from attached policies.
	for _, n := range nodes {
		if n.Type == "identity.policy" {
			g.privilege[n.ID] = policyPrivilege(n.Configuration)
		}
	}
	for _, e := range edges {
		if e.Type == "attached_to" && g.Nodes[e.Source].Type == "identity.policy" && g.Nodes[e.Target].Type == "identity.role" {
			if p := g.privilege[e.Source]; p > g.privilege[e.Target] {
				g.privilege[e.Target] = p
			}
		}
	}

	// Internet exposure.
	for _, n := range nodes {
		switch n.Type {
		case "network.load_balancer":
			if n.Configuration["internal"] == false {
				g.exposed[n.ID] = "internet-facing load balancer"
			}
		case "storage.bucket":
			if n.Configuration["public_access_block"] != true {
				g.exposed[n.ID] = "bucket does not block public access"
			}
		case "database.instance":
			if n.Configuration["publicly_accessible"] == true {
				g.exposed[n.ID] = "database is publicly accessible"
			}
		}
	}
	for _, e := range edges {
		sg, ok := g.Nodes[e.Source]
		if e.Type == "attached_to" && ok && sg.Type == "network.security_group" && openToInternet(sg.Configuration) {
			if _, already := g.exposed[e.Target]; !already {
				g.exposed[e.Target] = "attached security group " + sg.ID + " allows ingress from the internet"
			}
		}
	}
	ids := make([]string, 0, len(g.exposed))
	for id := range g.exposed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		add(Hop{From: Internet, To: id, Via: "exposure", Reason: g.exposed[id]})
	}

	// Movement along stored relationships.
	for _, e := range edges {
		src, okS := g.Nodes[e.Source]
		dst, okT := g.Nodes[e.Target]
		if !okS || !okT {
			continue
		}
		switch e.Type {
		case "routes_to":
			add(Hop{From: e.Source, To: e.Target, Via: e.Type, Reason: "traffic is routed to the target"})
		case "assumes":
			add(Hop{From: e.Source, To: e.Target, Via: e.Type, Reason: "compromising the source yields the role's credentials"})
		case "reads_from", "writes_to":
			if dataStores[dst.Type] || src.Type == "compute.instance" {
				add(Hop{From: e.Source, To: e.Target, Via: e.Type, Reason: "the source has data access to the target"})
			}
		}
	}

	// Admin roles can reach every data store.
	var roles, stores []string
	for id, n := range g.Nodes {
		if n.Type == "identity.role" && g.privilege[id] == PrivAdmin {
			roles = append(roles, id)
		}
		if dataStores[n.Type] {
			stores = append(stores, id)
		}
	}
	sort.Strings(roles)
	sort.Strings(stores)
	for _, r := range roles {
		for _, s := range stores {
			add(Hop{From: r, To: s, Via: "admin_privilege", Reason: "role has a full-administrator policy (Action *, Resource *)"})
		}
	}
	for k := range g.out {
		sort.SliceStable(g.out[k], func(i, j int) bool { return g.out[k][i].To < g.out[k][j].To })
	}
	return g
}

func policyPrivilege(cfg map[string]any) int {
	stmts, _ := cfg["statements"].([]any)
	level := PrivNone
	for _, s := range stmts {
		m, _ := s.(map[string]any)
		if eff, _ := m["effect"].(string); !strings.EqualFold(eff, "allow") {
			continue
		}
		level = max(level, PrivScoped)
		if containsStar(m["actions"]) && containsStar(m["resources"]) {
			return PrivAdmin
		}
	}
	return level
}

func containsStar(v any) bool {
	switch t := v.(type) {
	case string:
		return t == "*"
	case []any:
		for _, x := range t {
			if x == "*" {
				return true
			}
		}
	}
	return false
}

func openToInternet(cfg map[string]any) bool {
	rules, _ := cfg["ingress"].([]any)
	for _, r := range rules {
		m, _ := r.(map[string]any)
		for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
			list, _ := m[key].([]any)
			for _, c := range list {
				if c == "0.0.0.0/0" || c == "::/0" {
					return true
				}
			}
		}
	}
	return false
}

// Sensitivity estimates how damaging exposure of a resource's data would be.
// A data_classification tag overrides the heuristic.
func Sensitivity(n Node) int {
	switch strings.ToLower(n.Tags["data_classification"]) {
	case "restricted", "confidential":
		return 100
	case "internal":
		return 50
	case "public":
		return 0
	}
	prod := n.Environment == "production"
	switch n.Type {
	case "database.instance":
		if prod {
			return 90
		}
		return 60
	case "storage.bucket":
		if prod {
			return 80
		}
		return 50
	}
	return 0
}

// Exposed returns why a node is directly internet-exposed ("" if it is not).
func (g *Graph) Exposed(id string) string { return g.exposed[id] }

// Privilege of a node: its own (role/policy) or that of a role it assumes.
func (g *Graph) Privilege(id string) int {
	p := g.privilege[id]
	for _, h := range g.out[id] {
		if h.Via == "assumes" {
			switch g.privilege[h.To] {
			case PrivAdmin:
				p = max(p, 80)
			case PrivScoped:
				p = max(p, 30)
			}
		}
	}
	return p
}

// MaxDepth bounds every traversal.
const MaxDepth = 6

// shortest returns BFS predecessor hops from start (bounded depth).
func (g *Graph) shortest(start string) map[string]Hop {
	prev := map[string]Hop{}
	seen := map[string]bool{start: true}
	frontier := []string{start}
	for depth := 0; depth < MaxDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, n := range frontier {
			for _, h := range g.out[n] {
				if seen[h.To] {
					continue
				}
				seen[h.To] = true
				prev[h.To] = h
				next = append(next, h.To)
			}
		}
		frontier = next
	}
	return prev
}

func unwind(prev map[string]Hop, start, target string) []Hop {
	var hops []Hop
	for at := target; at != start; {
		h, ok := prev[at]
		if !ok {
			return nil
		}
		hops = append([]Hop{h}, hops...)
		at = h.From
	}
	return hops
}

// InternetReach computes shortest paths from the internet once.
func (g *Graph) InternetReach() map[string]Hop { return g.shortest(Internet) }

// BlastRadius returns the sensitive data stores reachable from id and the
// highest sensitivity among them (including id itself).
func (g *Graph) BlastRadius(id string) (stores []string, maxSensitivity int) {
	maxSensitivity = Sensitivity(g.Nodes[id])
	for to := range g.shortest(id) {
		n := g.Nodes[to]
		if !dataStores[n.Type] {
			continue
		}
		if s := Sensitivity(n); s >= 50 {
			stores = append(stores, to)
			maxSensitivity = max(maxSensitivity, s)
		}
	}
	sort.Strings(stores)
	return stores, maxSensitivity
}

// AttackPaths returns the shortest internet path to every reachable data
// store with sensitivity >= minSensitivity, most sensitive and shortest first.
func (g *Graph) AttackPaths(minSensitivity, limit int) []Path {
	prev := g.InternetReach()
	var paths []Path
	for id, n := range g.Nodes {
		if !dataStores[n.Type] {
			continue
		}
		s := Sensitivity(n)
		if s < minSensitivity {
			continue
		}
		if hops := unwind(prev, Internet, id); hops != nil {
			paths = append(paths, Path{Target: id, TargetType: n.Type, Sensitivity: s, Hops: hops})
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		a, b := paths[i], paths[j]
		if a.Sensitivity != b.Sensitivity {
			return a.Sensitivity > b.Sensitivity
		}
		if len(a.Hops) != len(b.Hops) {
			return len(a.Hops) < len(b.Hops)
		}
		return a.Target < b.Target
	})
	if limit > 0 && len(paths) > limit {
		paths = paths[:limit]
	}
	return paths
}

// NodeFromJSON builds a node from stored JSON columns.
func NodeFromJSON(id, typ, env string, tags, cfg []byte) (Node, error) {
	n := Node{ID: id, Type: typ, Environment: env}
	if err := json.Unmarshal(tags, &n.Tags); err != nil {
		return n, err
	}
	return n, json.Unmarshal(cfg, &n.Configuration)
}
