package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// IPBlocklist represents the loaded and optimized blocklist
type IPBlocklist struct {
	LastUpdated time.Time `json:"last_updated"`
	TotalIPs    int       `json:"total_ips"`
	TotalRanges int       `json:"total_ranges"`
	Sources     []string  `json:"sources"`
	CIDRRanges  []string  `json:"cidr_ranges"`
	
	// Optimized lookup structures (not serialized)
	ipv4Tree *IPv4RadixTree `json:"-"`
	ipv6Nets []*net.IPNet   `json:"-"` // IPv6 less common, simple slice lookup
}

// IPv4RadixTree provides fast IP lookup for IPv4 addresses
type IPv4RadixTree struct {
	root *IPv4Node
}

type IPv4Node struct {
	isBlocked bool
	left      *IPv4Node // 0 bit
	right     *IPv4Node // 1 bit
}

// Global IP blocklist with thread-safe access
var (
	currentBlocklist *IPBlocklist
	blocklistMutex   sync.RWMutex
	blocklistFile    = getEnv("CACHE_IP_BLOCKLIST", "./blocklist.json")
)

// Initialize the IP blocking system
func initIPBlocklist() {
	if blocklistFile == "" {
		log.Printf("IP blocking disabled - no blocklist file specified")
		return
	}
	
	if err := loadIPBlocklist(blocklistFile); err != nil {
		log.Printf("Warning: Failed to load IP blocklist from %s: %v", blocklistFile, err)
		log.Printf("IP blocking disabled")
		return
	}
	
	log.Printf("IP blocklist loaded: %d ranges covering %d IPs from %d sources",
		currentBlocklist.TotalRanges, currentBlocklist.TotalIPs, len(currentBlocklist.Sources))
}

// Load IP blocklist from file and build optimized lookup structures
func loadIPBlocklist(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("reading file: %v", err)
	}
	
	var blocklist IPBlocklist
	if err := json.Unmarshal(data, &blocklist); err != nil {
		return fmt.Errorf("parsing JSON: %v", err)
	}
	
	// Build optimized lookup structures
	blocklist.ipv4Tree = NewIPv4RadixTree()
	var ipv6Nets []*net.IPNet
	
	for _, cidrStr := range blocklist.CIDRRanges {
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			log.Printf("Warning: invalid CIDR %s: %v", cidrStr, err)
			continue
		}
		
		// Check if it's IPv4 or IPv6
		if ipNet.IP.To4() != nil {
			// IPv4 - add to radix tree
			blocklist.ipv4Tree.AddNetwork(ipNet)
		} else {
			// IPv6 - add to slice (less common)
			ipv6Nets = append(ipv6Nets, ipNet)
		}
	}
	
	blocklist.ipv6Nets = ipv6Nets
	
	// Atomically update the global blocklist
	blocklistMutex.Lock()
	currentBlocklist = &blocklist
	blocklistMutex.Unlock()
	
	return nil
}

// Reload IP blocklist (for hot reloading)
func reloadIPBlocklist() error {
	if blocklistFile == "" {
		return fmt.Errorf("no blocklist file configured")
	}
	return loadIPBlocklist(blocklistFile)
}

// Check if an IP address is blocked
func isIPBlocked(ipStr string) bool {
	blocklistMutex.RLock()
	defer blocklistMutex.RUnlock()
	
	if currentBlocklist == nil {
		return false // No blocklist loaded
	}
	
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Invalid IP
	}
	
	// Check IPv4
	if ipv4 := ip.To4(); ipv4 != nil {
		return currentBlocklist.ipv4Tree.Contains(ipv4)
	}
	
	// Check IPv6 (linear search - less common)
	for _, ipNet := range currentBlocklist.ipv6Nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	
	return false
}

// NewIPv4RadixTree creates a new empty radix tree for IPv4 lookups
func NewIPv4RadixTree() *IPv4RadixTree {
	return &IPv4RadixTree{
		root: &IPv4Node{},
	}
}

// AddNetwork adds a CIDR network to the radix tree
func (tree *IPv4RadixTree) AddNetwork(ipNet *net.IPNet) {
	ip := ipNet.IP.To4()
	if ip == nil {
		return // Not IPv4
	}
	
	// Convert IP to uint32 for bit manipulation
	ipInt := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	
	// Get network mask length
	ones, _ := ipNet.Mask.Size()
	
	// Traverse tree and mark blocked
	node := tree.root
	for i := 0; i < ones; i++ {
		bit := (ipInt >> (31 - i)) & 1
		if bit == 0 {
			if node.left == nil {
				node.left = &IPv4Node{}
			}
			node = node.left
		} else {
			if node.right == nil {
				node.right = &IPv4Node{}
			}
			node = node.right
		}
	}
	
	// Mark this node as blocked (covers entire subtree)
	node.isBlocked = true
}

// Contains checks if an IPv4 address is in any blocked network
func (tree *IPv4RadixTree) Contains(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	
	// Convert IP to uint32
	ipInt := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	
	// Traverse tree following IP bits
	node := tree.root
	for i := 0; i < 32; i++ {
		// If current node is blocked, this IP is blocked
		if node.isBlocked {
			return true
		}
		
		// Follow the bit path
		bit := (ipInt >> (31 - i)) & 1
		if bit == 0 {
			if node.left == nil {
				break // No more specific matches
			}
			node = node.left
		} else {
			if node.right == nil {
				break // No more specific matches
			}
			node = node.right
		}
	}
	
	// Check final node
	return node.isBlocked
}

// Extract IP address from request, handling proxies and load balancers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (original client)
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header (Nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	
	// Check CF-Connecting-IP (Cloudflare)
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		return strings.TrimSpace(cfip)
	}
	
	// Fall back to remote address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Get blocklist statistics
func getBlocklistStats() map[string]interface{} {
	blocklistMutex.RLock()
	defer blocklistMutex.RUnlock()
	
	if currentBlocklist == nil {
		return map[string]interface{}{
			"enabled":      false,
			"last_updated": nil,
		}
	}
	
	return map[string]interface{}{
		"enabled":      true,
		"last_updated": currentBlocklist.LastUpdated,
		"total_ips":    currentBlocklist.TotalIPs,
		"total_ranges": currentBlocklist.TotalRanges,
		"sources":      currentBlocklist.Sources,
	}
}