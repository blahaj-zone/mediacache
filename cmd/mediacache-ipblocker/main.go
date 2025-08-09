package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/bits"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	VERSION = "1.0.0"
	DEFAULT_OUTPUT_FILE = "./blocklist.json"
	USER_AGENT = "mediacache-ipblocker/" + VERSION
)

// Blocklist sources with their formats and update frequencies
type BlocklistSource struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Format      string `json:"format"` // "plain", "json", "csv", "nginx"
	Description string `json:"description"`
	UpdateFreq  string `json:"update_freq"`
	Enabled     bool   `json:"enabled"`
}

// Default blocklist sources
var defaultSources = []BlocklistSource{
	{
		Name:        "firehol-level1",
		URL:         "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		Format:      "plain",
		Description: "FireHOL Level 1 - attacks, malware, botnets",
		UpdateFreq:  "hourly",
		Enabled:     true,
	},
	{
		Name:        "nginx-badbot-ips",
		URL:         "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-ip-addresses.list",
		Format:      "plain", 
		Description: "Bad bot IPs from nginx blocker",
		UpdateFreq:  "daily",
		Enabled:     true,
	},
	{
		Name:        "abuse-ch-botnet",
		URL:         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 
		Format:      "plain",
		Description: "Botnet IPs from abuse.ch",
		UpdateFreq:  "daily",
		Enabled:     true,
	},
	{
		Name:        "spamhaus-drop",
		URL:         "https://www.spamhaus.org/drop/drop.txt",
		Format:      "plain",
		Description: "Spamhaus DROP list",
		UpdateFreq:  "daily", 
		Enabled:     true,
	},
	{
		Name:        "emergingthreats-compromised",
		URL:         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
		Format:      "plain",
		Description: "Compromised IPs from ET",
		UpdateFreq:  "daily",
		Enabled:     true,
	},
}

// Configuration structure
type Config struct {
	Sources    []BlocklistSource `json:"sources"`
	OutputFile string           `json:"output_file"`
	UserAgent  string           `json:"user_agent"`
	Timeout    int              `json:"timeout_seconds"`
}

// ProcessedBlocklist represents the final optimized structure
type ProcessedBlocklist struct {
	LastUpdated time.Time    `json:"last_updated"`
	TotalIPs    int          `json:"total_ips"`
	TotalRanges int          `json:"total_ranges"`
	Sources     []string     `json:"sources"`
	CIDRRanges  []string     `json:"cidr_ranges"`
}

var (
	configFile = flag.String("config", "", "Configuration file path")
	outputFile = flag.String("output", DEFAULT_OUTPUT_FILE, "Output file for processed blocklist")
	verbose    = flag.Bool("verbose", false, "Verbose logging")
	dryRun     = flag.Bool("dry-run", false, "Don't write output file, just process and show stats")
)

func main() {
	flag.Parse()
	
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	
	log.Printf("mediacache-ipblocker %s starting", VERSION)
	
	// Load or create configuration
	config := loadConfig(*configFile)
	if *outputFile != DEFAULT_OUTPUT_FILE {
		config.OutputFile = *outputFile
	}
	
	// Process all enabled sources
	allRanges := make(map[string]bool) // Use map for deduplication
	var activeSources []string
	
	for _, source := range config.Sources {
		if !source.Enabled {
			continue
		}
		
		log.Printf("Processing source: %s", source.Name)
		ranges, err := fetchAndParseSource(source, config)
		if err != nil {
			log.Printf("Error processing %s: %v", source.Name, err)
			continue
		}
		
		activeSources = append(activeSources, source.Name)
		for _, cidr := range ranges {
			allRanges[cidr] = true
		}
		
		if *verbose {
			log.Printf("  Added %d ranges from %s", len(ranges), source.Name)
		}
	}
	
	// Convert map back to sorted slice
	var finalRanges []string
	for cidr := range allRanges {
		finalRanges = append(finalRanges, cidr)
	}
	sort.Strings(finalRanges)
	
	// Optimize and merge overlapping ranges
	optimizedRanges := optimizeCIDRRanges(finalRanges)
	
	// Create final blocklist
	blocklist := ProcessedBlocklist{
		LastUpdated: time.Now(),
		TotalIPs:    countIPsInRanges(optimizedRanges),
		TotalRanges: len(optimizedRanges),
		Sources:     activeSources,
		CIDRRanges:  optimizedRanges,
	}
	
	log.Printf("Processed blocklist: %d ranges covering %d IPs from %d sources",
		blocklist.TotalRanges, blocklist.TotalIPs, len(blocklist.Sources))
	
	if *dryRun {
		log.Printf("Dry run mode - not writing to %s", config.OutputFile)
		return
	}
	
	// Write output file
	if err := writeBlocklist(config.OutputFile, blocklist); err != nil {
		log.Fatalf("Error writing blocklist: %v", err)
	}
	
	log.Printf("Successfully wrote blocklist to %s", config.OutputFile)
}

func loadConfig(configPath string) Config {
	config := Config{
		Sources:    defaultSources,
		OutputFile: DEFAULT_OUTPUT_FILE,
		UserAgent:  USER_AGENT,
		Timeout:    30,
	}
	
	if configPath == "" {
		return config
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Could not read config file %s: %v, using defaults", configPath, err)
		return config
	}
	
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Could not parse config file %s: %v, using defaults", configPath, err)
		return config
	}
	
	log.Printf("Loaded configuration from %s", configPath)
	return config
}

func fetchAndParseSource(source BlocklistSource, config Config) ([]string, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}
	
	// Create request with proper user agent
	req, err := http.NewRequest("GET", source.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %v", err)
	}
	req.Header.Set("User-Agent", config.UserAgent)
	
	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching data: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	// Handle gzipped content
	var reader io.Reader = resp.Body
	if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("decompressing: %v", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	}
	
	// Parse based on format
	return parseIPList(reader, source.Format)
}

func parseIPList(reader io.Reader, format string) ([]string, error) {
	var ranges []string
	scanner := bufio.NewScanner(reader)
	
	// Regex patterns for IP detection
	ipv4Pattern := regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d{1,2}))?`)
	ipv6Pattern := regexp.MustCompile(`^([0-9a-fA-F:]{2,39})(?:/(\d{1,3}))?`)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		
		// Extract IP/CIDR from line based on format
		var ipStr string
		switch format {
		case "plain":
			ipStr = line
		case "nginx":
			// Handle nginx format: "deny 1.2.3.4;"
			if strings.HasPrefix(line, "deny ") && strings.HasSuffix(line, ";") {
				ipStr = strings.TrimSuffix(strings.TrimPrefix(line, "deny "), ";")
				ipStr = strings.TrimSpace(ipStr)
			}
		default:
			ipStr = line
		}
		
		if ipStr == "" {
			continue
		}
		
		// Try to parse as IPv4 first
		if matches := ipv4Pattern.FindStringSubmatch(ipStr); matches != nil {
			ip := matches[1]
			cidr := matches[2]
			
			// Validate IP
			if net.ParseIP(ip) == nil {
				continue
			}
			
			// Default to /32 for single IPs
			if cidr == "" {
				cidr = "32"
			}
			
			ranges = append(ranges, fmt.Sprintf("%s/%s", ip, cidr))
		} else if matches := ipv6Pattern.FindStringSubmatch(ipStr); matches != nil {
			// Handle IPv6 (less common in bot blocklists but good to support)
			ip := matches[1]
			cidr := matches[2]
			
			if net.ParseIP(ip) == nil {
				continue
			}
			
			if cidr == "" {
				cidr = "128"
			}
			
			ranges = append(ranges, fmt.Sprintf("%s/%s", ip, cidr))
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning input: %v", err)
	}
	
	return ranges, nil
}

// Optimize CIDR ranges by merging overlapping and adjacent ones
func optimizeCIDRRanges(ranges []string) []string {
	if len(ranges) == 0 {
		return ranges
	}
	
	// Parse all ranges and separate IPv4/IPv6
	var ipv4Nets, ipv6Nets []*net.IPNet
	for _, rangeStr := range ranges {
		_, ipNet, err := net.ParseCIDR(rangeStr)
		if err != nil {
			if *verbose {
				log.Printf("Skipping invalid CIDR: %s", rangeStr)
			}
			continue
		}
		
		if ipNet.IP.To4() != nil {
			ipv4Nets = append(ipv4Nets, ipNet)
		} else {
			ipv6Nets = append(ipv6Nets, ipNet)
		}
	}
	
	// Optimize IPv4 and IPv6 separately with progress logging
	if *verbose {
		log.Printf("Optimizing %d IPv4 ranges and %d IPv6 ranges", len(ipv4Nets), len(ipv6Nets))
	}
	
	optimizedIPv4 := optimizeRanges(ipv4Nets)
	if *verbose {
		log.Printf("IPv4 optimization: %d -> %d ranges", len(ipv4Nets), len(optimizedIPv4))
	}
	
	optimizedIPv6 := optimizeRanges(ipv6Nets)
	if *verbose {
		log.Printf("IPv6 optimization: %d -> %d ranges", len(ipv6Nets), len(optimizedIPv6))
	}
	
	// Combine results
	var result []string
	for _, net := range optimizedIPv4 {
		result = append(result, net.String())
	}
	for _, net := range optimizedIPv6 {
		result = append(result, net.String())
	}
	
	sort.Strings(result)
	return result
}

// Optimize CIDR ranges - remove duplicates, contained ranges, and merge adjacent IPv4 ranges
func optimizeRanges(nets []*net.IPNet) []*net.IPNet {
	if len(nets) == 0 {
		return nets
	}
	
	// Remove exact duplicates
	seen := make(map[string]*net.IPNet)
	for _, net := range nets {
		key := net.String()
		seen[key] = net
	}
	
	// Convert back to slice
	var unique []*net.IPNet
	for _, net := range seen {
		unique = append(unique, net)
	}
	
	// Remove ranges that are fully contained in others
	var filtered []*net.IPNet
	for i, net1 := range unique {
		contained := false
		for j, net2 := range unique {
			if i != j && isContained(net1, net2) {
				contained = true
				break
			}
		}
		if !contained {
			filtered = append(filtered, net1)
		}
	}
	
	// Simple adjacent merging for IPv4 only (IPv6 is more complex)
	var ipv4Nets, ipv6Nets []*net.IPNet
	for _, net := range filtered {
		if net.IP.To4() != nil {
			ipv4Nets = append(ipv4Nets, net)
		} else {
			ipv6Nets = append(ipv6Nets, net)
		}
	}
	
	// Merge adjacent IPv4 ranges
	mergedIPv4 := mergeAdjacentIPv4(ipv4Nets)
	
	// Combine results
	var result []*net.IPNet
	result = append(result, mergedIPv4...)
	result = append(result, ipv6Nets...)
	
	return result
}

// Merge adjacent IPv4 CIDR ranges
func mergeAdjacentIPv4(nets []*net.IPNet) []*net.IPNet {
	if len(nets) <= 1 {
		return nets
	}
	
	
	// Convert networks to intervals
	var intervals []ipv4Interval
	for _, net := range nets {
		ip := net.IP.To4()
		if ip == nil {
			continue
		}
		
		start := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		ones, bits := net.Mask.Size()
		if bits != 32 {
			continue
		}
		
		size := uint32(1) << (32 - ones)
		end := start + size - 1
		
		intervals = append(intervals, ipv4Interval{start: start, end: end, net: net})
	}
	
	// Sort by start address
	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i].start < intervals[j].start
	})
	
	// Merge overlapping and adjacent intervals
	var merged []ipv4Interval
	for _, current := range intervals {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		
		last := &merged[len(merged)-1]
		
		// Merge if overlapping or adjacent
		if current.start <= last.end+1 {
			if current.end > last.end {
				last.end = current.end
			}
		} else {
			merged = append(merged, current)
		}
	}
	
	// Convert back to CIDR ranges
	var result []*net.IPNet
	for _, interval := range merged {
		if interval.start == interval.end {
			// Single IP
			result = append(result, createSingleIPCIDR(interval.start))
		} else {
			// Try to preserve original CIDR if it matches exactly
			if interval.net != nil && intervalMatchesNetwork(interval, interval.net) {
				result = append(result, interval.net)
			} else {
				// Break into power-of-2 blocks
				result = append(result, intervalToPowerOf2CIDRs(interval.start, interval.end)...)
			}
		}
	}
	
	return result
}

// Create a /32 CIDR for a single IP
func createSingleIPCIDR(ip uint32) *net.IPNet {
	ipBytes := make(net.IP, 4)
	ipBytes[0] = byte(ip >> 24)
	ipBytes[1] = byte(ip >> 16)
	ipBytes[2] = byte(ip >> 8)
	ipBytes[3] = byte(ip)
	return &net.IPNet{IP: ipBytes, Mask: net.CIDRMask(32, 32)}
}

// IPv4 interval representation
type ipv4Interval struct {
	start uint32
	end   uint32
	net   *net.IPNet
}

// Check if interval matches the original network exactly
func intervalMatchesNetwork(interval ipv4Interval, net *net.IPNet) bool {
	ip := net.IP.To4()
	if ip == nil {
		return false
	}
	
	start := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	ones, _ := net.Mask.Size()
	size := uint32(1) << (32 - ones)
	
	return start == interval.start && size == (interval.end-interval.start+1)
}

// Convert IP interval to power-of-2 CIDR blocks
func intervalToPowerOf2CIDRs(start, end uint32) []*net.IPNet {
	var cidrs []*net.IPNet
	current := start
	
	for current <= end {
		// Find largest aligned power-of-2 block that fits
		remaining := end - current + 1
		blockSize := uint32(1)
		
		// Find largest power of 2 that fits and is properly aligned
		for blockSize <= remaining && (current&(blockSize-1)) == 0 && blockSize <= (1<<20) {
			blockSize <<= 1
		}
		blockSize >>= 1
		
		if blockSize == 0 {
			blockSize = 1
		}
		
		// Create CIDR for this block
		prefixLen := 32 - bits.Len32(blockSize-1)
		if prefixLen < 0 || prefixLen > 32 {
			prefixLen = 32
		}
		
		ip := make(net.IP, 4)
		ip[0] = byte(current >> 24)
		ip[1] = byte(current >> 16)
		ip[2] = byte(current >> 8)
		ip[3] = byte(current)
		
		mask := net.CIDRMask(prefixLen, 32)
		cidrs = append(cidrs, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
		
		current += blockSize
	}
	
	return cidrs
}


// Check if net1 is fully contained within net2
func isContained(net1, net2 *net.IPNet) bool {
	ones1, bits1 := net1.Mask.Size()
	ones2, bits2 := net2.Mask.Size()
	
	// Different IP versions
	if bits1 != bits2 {
		return false
	}
	
	// net1 can only be contained in net2 if net2 has fewer host bits (larger network)
	if ones2 > ones1 {
		return false
	}
	
	// Check if net1's network address falls within net2
	return net2.Contains(net1.IP)
}

// Count approximate number of IPs in CIDR ranges
func countIPsInRanges(ranges []string) int {
	total := 0
	for _, rangeStr := range ranges {
		_, ipNet, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		
		// Calculate number of IPs in this network
		ones, bits := ipNet.Mask.Size()
		if bits == 32 { // IPv4
			total += 1 << (32 - ones)
		} else if bits == 128 { // IPv6 - limit to reasonable estimate
			hostBits := bits - ones
			if hostBits > 32 {
				total += 1 << 32 // Cap at IPv4 space for estimation
			} else {
				total += 1 << hostBits
			}
		}
	}
	return total
}

func writeBlocklist(filename string, blocklist ProcessedBlocklist) error {
	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory: %v", err)
	}
	
	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(blocklist, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %v", err)
	}
	
	// Generate unique temporary filename with PID and timestamp to avoid conflicts
	tempFile := fmt.Sprintf("%s.tmp.%d.%d", filename, os.Getpid(), time.Now().UnixNano())
	
	// Write to temporary file first
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("writing temporary file: %v", err)
	}
	
	// Ensure data is synced to disk before rename
	if file, err := os.OpenFile(tempFile, os.O_RDWR, 0644); err == nil {
		file.Sync() // Force sync to disk
		file.Close()
	}
	
	// Atomic rename operation
	if err := os.Rename(tempFile, filename); err != nil {
		os.Remove(tempFile) // Clean up on failure
		return fmt.Errorf("renaming file: %v", err)
	}
	
	return nil
}