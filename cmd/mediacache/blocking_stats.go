package main

import (
	"strings"
	"sync/atomic"
	"time"
)

// BlockingStats tracks detailed statistics for bot blocking
type BlockingStats struct {
	// IP-based blocking stats
	IPBlocks        int64 `json:"ip_blocks"`
	IPBlocksToday   int64 `json:"ip_blocks_today"`
	
	// User-agent based blocking stats  
	UABlocks        int64 `json:"ua_blocks"`
	UABlocksToday   int64 `json:"ua_blocks_today"`
	
	// Combined stats
	TotalBlocks     int64 `json:"total_blocks"`
	TotalBlocksToday int64 `json:"total_blocks_today"`
	
	// Top blocked user agents (simplified - just counters for major categories)
	AIBotsBlocked        int64 `json:"ai_bots_blocked"`
	SearchBotsBlocked    int64 `json:"search_bots_blocked"`
	SocialBotsBlocked    int64 `json:"social_bots_blocked"`
	ScrapersBlocked      int64 `json:"scrapers_blocked"`
	OtherBotsBlocked     int64 `json:"other_bots_blocked"`
	
	// Daily reset tracking
	LastResetDate string `json:"last_reset_date"`
}

// Global blocking stats
var blockingStats BlockingStats

// Initialize blocking stats
func initBlockingStats() {
	today := time.Now().Format("2006-01-02")
	blockingStats.LastResetDate = today
}

// Check if we need to reset daily counters
func checkDailyReset() {
	today := time.Now().Format("2006-01-02")
	if blockingStats.LastResetDate != today {
		// Reset daily counters
		atomic.StoreInt64(&blockingStats.IPBlocksToday, 0)
		atomic.StoreInt64(&blockingStats.UABlocksToday, 0)
		atomic.StoreInt64(&blockingStats.TotalBlocksToday, 0)
		blockingStats.LastResetDate = today
	}
}

// Record an IP-based block
func recordIPBlock() {
	checkDailyReset()
	atomic.AddInt64(&blockingStats.IPBlocks, 1)
	atomic.AddInt64(&blockingStats.IPBlocksToday, 1)
	atomic.AddInt64(&blockingStats.TotalBlocks, 1)
	atomic.AddInt64(&blockingStats.TotalBlocksToday, 1)
}

// Record a user-agent based block with categorization
func recordUABlock(userAgent string) {
	checkDailyReset()
	atomic.AddInt64(&blockingStats.UABlocks, 1)
	atomic.AddInt64(&blockingStats.UABlocksToday, 1)
	atomic.AddInt64(&blockingStats.TotalBlocks, 1)
	atomic.AddInt64(&blockingStats.TotalBlocksToday, 1)
	
	// Categorize the user agent
	ua := strings.ToLower(userAgent)
	
	// AI/LLM bots
	if containsAny(ua, []string{"gpt", "chatgpt", "claude", "anthropic", "ccbot", 
		"perplexity", "openai", "ai2bot", "cohere", "google-extended"}) {
		atomic.AddInt64(&blockingStats.AIBotsBlocked, 1)
	} else if containsAny(ua, []string{"googlebot", "bingbot", "slurp", "duckduckbot", 
		"baiduspider", "yandexbot"}) {
		atomic.AddInt64(&blockingStats.SearchBotsBlocked, 1)
	} else if containsAny(ua, []string{"facebook", "twitter", "linkedin", "whatsapp", 
		"telegram"}) {
		atomic.AddInt64(&blockingStats.SocialBotsBlocked, 1)
	} else if containsAny(ua, []string{"scraper", "scrapy", "crawler", "spider", 
		"wget", "curl", "python", "java", "node"}) {
		atomic.AddInt64(&blockingStats.ScrapersBlocked, 1)
	} else {
		atomic.AddInt64(&blockingStats.OtherBotsBlocked, 1)
	}
}

// Helper function to check if string contains any of the patterns
func containsAny(s string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	return false
}

// Get current blocking statistics
func getBlockingStats() BlockingStats {
	checkDailyReset()
	
	// Return a copy with current atomic values
	return BlockingStats{
		IPBlocks:             atomic.LoadInt64(&blockingStats.IPBlocks),
		IPBlocksToday:        atomic.LoadInt64(&blockingStats.IPBlocksToday),
		UABlocks:             atomic.LoadInt64(&blockingStats.UABlocks),
		UABlocksToday:        atomic.LoadInt64(&blockingStats.UABlocksToday),
		TotalBlocks:          atomic.LoadInt64(&blockingStats.TotalBlocks),
		TotalBlocksToday:     atomic.LoadInt64(&blockingStats.TotalBlocksToday),
		AIBotsBlocked:        atomic.LoadInt64(&blockingStats.AIBotsBlocked),
		SearchBotsBlocked:    atomic.LoadInt64(&blockingStats.SearchBotsBlocked),
		SocialBotsBlocked:    atomic.LoadInt64(&blockingStats.SocialBotsBlocked),
		ScrapersBlocked:      atomic.LoadInt64(&blockingStats.ScrapersBlocked),
		OtherBotsBlocked:     atomic.LoadInt64(&blockingStats.OtherBotsBlocked),
		LastResetDate:        blockingStats.LastResetDate,
	}
}