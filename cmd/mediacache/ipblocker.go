package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
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
	reloadInterval   = time.Duration(getEnv[int64]("CACHE_IP_RELOAD_MINUTES", 30)) * time.Minute
	trustedProxies   []*net.IPNet
	trustedProxiesMutex sync.RWMutex
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
	
	// Initialize trusted proxies
	initTrustedProxies()
	
	// Start periodic reload with jitter
	if reloadInterval > 0 {
		go startPeriodicReload()
	}
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

// Start periodic reload with jitter to prevent thundering herd
func startPeriodicReload() {
	// Add random jitter: ±25% of reload interval (max 15 minutes for 30min interval)
	jitterRange := reloadInterval / 4
	jitterMax := big.NewInt(int64(jitterRange.Nanoseconds()))
	
	for {
		// Generate random jitter
		jitterNanos, err := rand.Int(rand.Reader, jitterMax)
		if err != nil {
			// Fallback to base interval if random fails
			time.Sleep(reloadInterval)
		} else {
			// Apply jitter: base interval ± random amount
			jitter := time.Duration(jitterNanos.Int64()) - jitterRange/2
			actualInterval := reloadInterval + jitter
			
			log.Printf("Next IP blocklist reload in %v", actualInterval)
			time.Sleep(actualInterval)
		}
		
		// Attempt to reload
		if err := reloadIPBlocklist(); err != nil {
			log.Printf("Failed to reload IP blocklist: %v", err)
		} else {
			blocklistMutex.RLock()
			if currentBlocklist != nil {
				log.Printf("IP blocklist reloaded: %d ranges covering %d IPs from %d sources",
					currentBlocklist.TotalRanges, currentBlocklist.TotalIPs, len(currentBlocklist.Sources))
			}
			blocklistMutex.RUnlock()
		}
	}
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

// Initialize trusted proxy networks
func initTrustedProxies() {
	trustedProxyCIDRs := getEnv("CACHE_TRUSTED_PROXIES", "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	
	if trustedProxyCIDRs == "" {
		log.Printf("No trusted proxies configured")
		return
	}
	
	var proxies []*net.IPNet
	for _, cidr := range strings.Split(trustedProxyCIDRs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Invalid trusted proxy CIDR %s: %v", cidr, err)
			continue
		}
		
		proxies = append(proxies, ipNet)
	}
	
	trustedProxiesMutex.Lock()
	trustedProxies = proxies
	trustedProxiesMutex.Unlock()
	
	log.Printf("Loaded %d trusted proxy ranges", len(proxies))
}

// Check if an IP is a trusted proxy
func isTrustedProxy(ip string) bool {
	trustedProxiesMutex.RLock()
	defer trustedProxiesMutex.RUnlock()
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	for _, network := range trustedProxies {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// Check if ANY IP in the request chain is blocked
func isRequestBlocked(r *http.Request) (bool, string, string) {
	// Get direct connection IP
	directIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		directIP = r.RemoteAddr
	}
	
	// Collect all IPs in the request chain
	var chainIPs []string
	var headers []string
	
	// Always include direct connection IP unless it's trusted
	if !isTrustedProxy(directIP) {
		chainIPs = append(chainIPs, directIP)
		headers = append(headers, "RemoteAddr")
	}
	
	// If direct IP is trusted, process proxy headers
	if isTrustedProxy(directIP) {
		// Check X-Forwarded-For chain (most common)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			for i, ip := range ips {
				ip = strings.TrimSpace(ip)
				if ip != "" && net.ParseIP(ip) != nil {
					chainIPs = append(chainIPs, ip)
					headers = append(headers, fmt.Sprintf("X-Forwarded-For[%d]", i))
				}
			}
		}
		
		// Check X-Real-IP header (Nginx)
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			ip := strings.TrimSpace(xri)
			if net.ParseIP(ip) != nil {
				chainIPs = append(chainIPs, ip)
				headers = append(headers, "X-Real-IP")
			}
		}
		
		// Check CF-Connecting-IP (Cloudflare)
		if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
			ip := strings.TrimSpace(cfip)
			if net.ParseIP(ip) != nil {
				chainIPs = append(chainIPs, ip)
				headers = append(headers, "CF-Connecting-IP")
			}
		}
	}
	
	// Check each IP in the chain
	for i, ip := range chainIPs {
		if isIPBlocked(ip) {
			return true, ip, headers[i]
		}
	}
	
	return false, "", ""
}

// Extract the best client IP from request (for logging/stats)
func getClientIP(r *http.Request) string {
	// Get direct connection IP
	directIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		directIP = r.RemoteAddr
	}
	
	// If direct IP is not trusted, use it
	if !isTrustedProxy(directIP) {
		return directIP
	}
	
	// Direct IP is trusted, look for client IP in headers
	// Try X-Forwarded-For first (get the first/leftmost IP which should be the original client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip != "" && net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	
	// Try X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	
	// Try CF-Connecting-IP
	if cfip := r.Header.Get("CF-Connecting-IP"); cfip != "" {
		ip := strings.TrimSpace(cfip)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	
	// Fallback to direct IP if no valid client IP found
	return directIP
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
	
	trustedProxiesMutex.RLock()
	trustedCount := len(trustedProxies)
	trustedProxiesMutex.RUnlock()
	
	return map[string]interface{}{
		"enabled":         true,
		"last_updated":    currentBlocklist.LastUpdated,
		"total_ips":       currentBlocklist.TotalIPs,
		"total_ranges":    currentBlocklist.TotalRanges,
		"sources":         currentBlocklist.Sources,
		"trusted_proxies": trustedCount,
	}
}