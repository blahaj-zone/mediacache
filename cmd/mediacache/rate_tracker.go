package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Rate tracking configuration
var (
	// Time windows for rate tracking
	shortWindow  = time.Duration(getEnv[int64]("CACHE_RATE_SHORT_WINDOW_MINUTES", 5)) * time.Minute
	longWindow   = time.Duration(getEnv[int64]("CACHE_RATE_LONG_WINDOW_MINUTES", 60)) * time.Minute
	
	// Rate thresholds for anomaly detection
	shortWindowThreshold = getEnv[int64]("CACHE_RATE_SHORT_THRESHOLD", 100) // requests per 5min
	longWindowThreshold  = getEnv[int64]("CACHE_RATE_LONG_THRESHOLD", 500)  // requests per hour
	
	// Logging configuration
	knownBotLogFile      = getEnv("CACHE_KNOWN_BOT_LOG", "./logs/known_bots.jsonl")
	suspectedBotLogFile  = getEnv("CACHE_SUSPECTED_BOT_LOG", "./logs/suspected_bots.jsonl")
	
	// Whitelisted IPs (different from trusted proxies)
	whitelistedIPs     []*net.IPNet
	whitelistMutex     sync.RWMutex
	
	// Rate tracking data structures
	ipRateTracker      = make(map[string]*IPRateData)
	rateTrackerMutex   sync.RWMutex
	
	// Cleanup ticker
	cleanupTicker      *time.Ticker
)

// IPRateData tracks request rates for a specific IP
type IPRateData struct {
	IP                string                `json:"ip"`
	FirstSeen         time.Time             `json:"first_seen"`
	LastSeen          time.Time             `json:"last_seen"`
	TotalRequests     int64                 `json:"total_requests"`
	
	// Time window buckets
	ShortWindowHits   []TimeBucket          `json:"short_window_hits"`
	LongWindowHits    []TimeBucket          `json:"long_window_hits"`
	
	// User agent tracking
	UserAgents        map[string]int64      `json:"user_agents"`
	
	// Bot detection flags
	IsKnownBot        bool                  `json:"is_known_bot"`
	IsSuspectedBot    bool                  `json:"is_suspected_bot"`
	SuspectedSince    *time.Time            `json:"suspected_since,omitempty"`
	
	// Rate statistics
	MaxShortRate      int64                 `json:"max_short_rate"`  // Peak requests per short window
	MaxLongRate       int64                 `json:"max_long_rate"`   // Peak requests per long window
	CurrentShortRate  int64                 `json:"current_short_rate"`
	CurrentLongRate   int64                 `json:"current_long_rate"`
	
	mutex             sync.RWMutex
}

// TimeBucket represents request counts in a time bucket
type TimeBucket struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
}

// BotLogEntry represents a log entry for bot activity
type BotLogEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"user_agent"`
	Path          string    `json:"path"`
	BotType       string    `json:"bot_type"` // "known" or "suspected"
	ShortRate     int64     `json:"short_rate"`
	LongRate      int64     `json:"long_rate"`
	TotalRequests int64     `json:"total_requests"`
	Reason        string    `json:"reason,omitempty"`
}

// Initialize rate tracking system
func initRateTracker() {
	// Initialize whitelisted IPs
	initWhitelistedIPs()
	
	// Start cleanup routine
	cleanupTicker = time.NewTicker(10 * time.Minute)
	go rateTrackerCleanup()
	
	log.Printf("Rate tracker initialized - Short window: %v (%d req threshold), Long window: %v (%d req threshold)", 
		shortWindow, shortWindowThreshold, longWindow, longWindowThreshold)
}

// Initialize whitelisted IP ranges
func initWhitelistedIPs() {
	whitelistCIDRs := getEnv("CACHE_WHITELISTED_IPS", "")
	
	if whitelistCIDRs == "" {
		log.Printf("No whitelisted IPs configured")
		return
	}
	
	var whitelist []*net.IPNet
	for _, cidr := range strings.Split(whitelistCIDRs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Invalid whitelisted IP CIDR %s: %v", cidr, err)
			continue
		}
		
		whitelist = append(whitelist, ipNet)
	}
	
	whitelistMutex.Lock()
	whitelistedIPs = whitelist
	whitelistMutex.Unlock()
	
	log.Printf("Loaded %d whitelisted IP ranges", len(whitelist))
}

// Check if an IP is whitelisted (exempt from rate tracking)
func isWhitelistedIP(ip string) bool {
	whitelistMutex.RLock()
	defer whitelistMutex.RUnlock()
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	for _, network := range whitelistedIPs {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// Track a request for rate monitoring
func trackRequest(clientIP, userAgent, path string) {
	// Skip whitelisted IPs
	if isWhitelistedIP(clientIP) {
		return
	}
	
	rateTrackerMutex.Lock()
	ipData, exists := ipRateTracker[clientIP]
	if !exists {
		ipData = &IPRateData{
			IP:            clientIP,
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
			TotalRequests: 0,
			UserAgents:    make(map[string]int64),
			IsKnownBot:    isBotUserAgent(userAgent),
		}
		ipRateTracker[clientIP] = ipData
	}
	rateTrackerMutex.Unlock()
	
	// Update IP data (thread-safe)
	ipData.mutex.Lock()
	defer ipData.mutex.Unlock()
	
	now := time.Now()
	ipData.LastSeen = now
	ipData.TotalRequests++
	
	// Track user agent
	ipData.UserAgents[userAgent]++
	
	// Update time buckets
	ipData.updateTimeBuckets(now)
	
	// Calculate current rates
	ipData.CurrentShortRate = ipData.calculateRate(ipData.ShortWindowHits, shortWindow)
	ipData.CurrentLongRate = ipData.calculateRate(ipData.LongWindowHits, longWindow)
	
	// Update peak rates
	if ipData.CurrentShortRate > ipData.MaxShortRate {
		ipData.MaxShortRate = ipData.CurrentShortRate
	}
	if ipData.CurrentLongRate > ipData.MaxLongRate {
		ipData.MaxLongRate = ipData.CurrentLongRate
	}
	
	// Check for anomalous behavior
	ipData.checkForAnomalies(userAgent, path)
}

// Update time buckets for rate tracking
func (ip *IPRateData) updateTimeBuckets(now time.Time) {
	// Round to minute for bucketing
	bucketTime := now.Truncate(time.Minute)
	
	// Update short window buckets
	ip.ShortWindowHits = ip.updateBuckets(ip.ShortWindowHits, bucketTime, shortWindow)
	
	// Update long window buckets  
	ip.LongWindowHits = ip.updateBuckets(ip.LongWindowHits, bucketTime, longWindow)
}

// Update bucket array with new timestamp
func (ip *IPRateData) updateBuckets(buckets []TimeBucket, timestamp time.Time, window time.Duration) []TimeBucket {
	cutoff := timestamp.Add(-window)
	
	// Find or create bucket for current timestamp
	bucketIndex := -1
	for i, bucket := range buckets {
		if bucket.Timestamp.Equal(timestamp) {
			bucketIndex = i
			break
		}
	}
	
	if bucketIndex >= 0 {
		// Update existing bucket
		buckets[bucketIndex].Count++
	} else {
		// Add new bucket
		buckets = append(buckets, TimeBucket{
			Timestamp: timestamp,
			Count:     1,
		})
	}
	
	// Remove old buckets outside window
	var filtered []TimeBucket
	for _, bucket := range buckets {
		if bucket.Timestamp.After(cutoff) {
			filtered = append(filtered, bucket)
		}
	}
	
	return filtered
}

// Calculate request rate from buckets
func (ip *IPRateData) calculateRate(buckets []TimeBucket, window time.Duration) int64 {
	cutoff := time.Now().Add(-window)
	var total int64
	
	for _, bucket := range buckets {
		if bucket.Timestamp.After(cutoff) {
			total += bucket.Count
		}
	}
	
	return total
}

// Check for anomalous behavior and log if necessary
func (ip *IPRateData) checkForAnomalies(userAgent, path string) {
	// Log known bots (for tracking legitimate bot activity)
	if ip.IsKnownBot {
		logBotActivity(ip.IP, userAgent, path, "known", ip.CurrentShortRate, ip.CurrentLongRate, ip.TotalRequests, "")
		return
	}
	
	// Check for suspected bot behavior
	isSuspicious := false
	var reasons []string
	
	// Rate-based detection
	if ip.CurrentShortRate > shortWindowThreshold {
		isSuspicious = true
		reasons = append(reasons, "high_short_rate")
	}
	
	if ip.CurrentLongRate > longWindowThreshold {
		isSuspicious = true
		reasons = append(reasons, "high_long_rate")
	}
	
	// User agent diversity detection (too many different UAs from same IP)
	if len(ip.UserAgents) > 10 {
		isSuspicious = true
		reasons = append(reasons, "ua_diversity")
	}
	
	// Pattern detection (single UA making many requests might be cloaking)
	for ua, count := range ip.UserAgents {
		if count > 50 && !isBotUserAgent(ua) {
			isSuspicious = true
			reasons = append(reasons, "ua_cloaking")
			break
		}
	}
	
	// If suspicious and not already flagged, mark as suspected bot
	if isSuspicious && !ip.IsSuspectedBot {
		ip.IsSuspectedBot = true
		now := time.Now()
		ip.SuspectedSince = &now
		
		reason := strings.Join(reasons, ",")
		logBotActivity(ip.IP, userAgent, path, "suspected", ip.CurrentShortRate, ip.CurrentLongRate, ip.TotalRequests, reason)
	} else if ip.IsSuspectedBot {
		// Continue logging suspected bot activity
		reason := strings.Join(reasons, ",")
		logBotActivity(ip.IP, userAgent, path, "suspected", ip.CurrentShortRate, ip.CurrentLongRate, ip.TotalRequests, reason)
	}
}

// Log bot activity to appropriate file
func logBotActivity(ip, userAgent, path, botType string, shortRate, longRate, totalRequests int64, reason string) {
	entry := BotLogEntry{
		Timestamp:     time.Now(),
		IP:            ip,
		UserAgent:     userAgent,
		Path:          path,
		BotType:       botType,
		ShortRate:     shortRate,
		LongRate:      longRate,
		TotalRequests: totalRequests,
		Reason:        reason,
	}
	
	var logFile string
	if botType == "known" {
		logFile = knownBotLogFile
	} else {
		logFile = suspectedBotLogFile
	}
	
	// Ensure log directory exists
	logDir := logFile[:strings.LastIndex(logFile, "/")]
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			log.Printf("Failed to create log directory %s: %v", logDir, err)
			return
		}
	}
	
	// Append to log file
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open log file %s: %v", logFile, err)
		return
	}
	defer file.Close()
	
	// Write JSON line
	if data, err := json.Marshal(entry); err == nil {
		file.WriteString(string(data) + "\n")
	}
}

// Cleanup old rate tracking data
func rateTrackerCleanup() {
	for range cleanupTicker.C {
		rateTrackerMutex.Lock()
		
		cutoff := time.Now().Add(-24 * time.Hour) // Keep data for 24 hours
		var toDelete []string
		
		for ip, data := range ipRateTracker {
			data.mutex.RLock()
			if data.LastSeen.Before(cutoff) {
				toDelete = append(toDelete, ip)
			}
			data.mutex.RUnlock()
		}
		
		// Delete old entries
		for _, ip := range toDelete {
			delete(ipRateTracker, ip)
		}
		
		rateTrackerMutex.Unlock()
		
		if len(toDelete) > 0 {
			log.Printf("Rate tracker cleanup: removed %d old entries", len(toDelete))
		}
	}
}

// Get rate tracking statistics
func getRateTrackerStats() map[string]interface{} {
	rateTrackerMutex.RLock()
	defer rateTrackerMutex.RUnlock()
	
	var totalTracked, knownBots, suspectedBots int
	var maxShortRate, maxLongRate int64
	
	for _, data := range ipRateTracker {
		data.mutex.RLock()
		totalTracked++
		if data.IsKnownBot {
			knownBots++
		}
		if data.IsSuspectedBot {
			suspectedBots++
		}
		if data.MaxShortRate > maxShortRate {
			maxShortRate = data.MaxShortRate
		}
		if data.MaxLongRate > maxLongRate {
			maxLongRate = data.MaxLongRate
		}
		data.mutex.RUnlock()
	}
	
	whitelistMutex.RLock()
	whitelistCount := len(whitelistedIPs)
	whitelistMutex.RUnlock()
	
	return map[string]interface{}{
		"total_tracked":      totalTracked,
		"known_bots":         knownBots,
		"suspected_bots":     suspectedBots,
		"whitelisted_ranges": whitelistCount,
		"max_short_rate":     maxShortRate,
		"max_long_rate":      maxLongRate,
		"short_threshold":    shortWindowThreshold,
		"long_threshold":     longWindowThreshold,
		"short_window_min":   int(shortWindow.Minutes()),
		"long_window_min":    int(longWindow.Minutes()),
	}
}