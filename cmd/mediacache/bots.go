package main

import (
	"log"
	"net/http"
	"os"
	"strings"
)

// Bot detection patterns for user agents
var botPatterns = []string{
	// AI and LLM crawlers
	"gptbot", "chatgpt", "ccbot", "claude", "anthropic",
	"perplexitybot", "youbot", "google-extended", "openai",
	"ai2bot", "scrapy", "cohere", "meta-external", "facebook",
	"applebot-extended", "bytespider",

	// Search engines
	"googlebot", "bingbot", "slurp", "duckduckbot",
	"baiduspider", "yandexbot",

	// Social media
	"facebookexternalhit", "twitterbot", "linkedinbot",
	"whatsapp", "telegrambot",

	// SEO and analytics bots
	"semrushbot", "ahrefsbot", "mj12bot", "dotbot",
	"blexbot", "siteauditbot", "megaindex", "searchmetricsbot",
	"sogou", "360spider",

	// Archive crawlers
	"ia_archiver", "wayback", "archive.org_bot",

	// Common tools and libraries
	"wget", "curl", "python-requests", "python-urllib",
	"libwww-perl", "headlesschrome", "phantomjs", "selenium",
	"nutch", "apache-httpclient", "go-http-client", "java",
	"jakarta", "node.js", "okhttp", "postman", "insomnia",

	// Monitoring
	"uptimerobot", "pingdom", "site24x7", "statuscake", "uptimia",

	// Image scrapers
	"imagesift", "picscout", "tineye",

	// Generic patterns (will be checked after social media whitelist)
	"bot", "crawler", "spider", "scraper",
	"headless", "phantom",
}

// Comprehensive list of known bot user agents (exact matches)
var knownBots = map[string]bool{
	"GPTBot":                          true,
	"ChatGPT-User":                    true,
	"CCBot":                           true,
	"Claude-Web":                      true,
	"anthropic-ai":                    true,
	"PerplexityBot":                   true,
	"YouBot":                          true,
	"Google-Extended":                 true,
	"ChatGPT":                         true,
	"OpenAI":                          true,
	"AI2Bot":                          true,
	"Ai2Bot":                          true,
	"Scrapy":                          true,
	"cohere-ai":                       true,
	"Meta-ExternalAgent":              true,
	"Meta-ExternalFetcher":            true,
	"FacebookBot":                     true,
	"Applebot-Extended":               true,
	"Bytespider":                      true,
	"Googlebot":                       true,
	"Bingbot":                         true,
	"Slurp":                           true,
	"DuckDuckBot":                     true,
	"Baiduspider":                     true,
	"YandexBot":                       true,
	"facebookexternalhit":             true,
	"Twitterbot":                      true,
	"LinkedInBot":                     true,
	"WhatsApp":                        true,
	"TelegramBot":                     true,
	"SemrushBot":                      true,
	"AhrefsBot":                       true,
	"MJ12bot":                         true,
	"DotBot":                          true,
	"BLEXBot":                         true,
	"SiteAuditBot":                    true,
	"MegaIndex":                       true,
	"SearchmetricsBot":                true,
	"Sogou":                           true,
	"360Spider":                       true,
	"ia_archiver":                     true,
	"Wayback":                         true,
	"archive.org_bot":                 true,
	"wget":                            true,
	"curl":                            true,
	"python-requests":                 true,
	"Python-urllib":                   true,
	"libwww-perl":                     true,
	"HeadlessChrome":                  true,
	"PhantomJS":                       true,
	"Selenium":                        true,
	"UptimeRobot":                     true,
	"Pingdom":                         true,
	"Site24x7":                        true,
	"StatusCake":                      true,
	"Uptimia":                         true,
	"ImageSift":                       true,
	"PicScout":                        true,
	"TinEye":                          true,
	"ImagesiftBot":                    true,
	"Nutch":                           true,
	"Apache-HttpClient":               true,
	"Go-http-client":                  true,
	"Java":                            true,
	"Jakarta Commons-HttpClient":      true,
	"Node.js":                         true,
	"okhttp":                          true,
	"PostmanRuntime":                  true,
	"Insomnia":                        true,
}

// Legitimate social media/chat platform bots that should be allowed
var legitimateSocialBots = []string{
	// Discord
	"discordbot",
	
	// Slack  
	"slackbot", "slack-imgproxy",
	
	// Microsoft Teams
	"microsoft teams", "msteams", "teams/", "skype for business",
	
	// Matrix protocol
	"matrix", "synapse", "element",
	
	// Other legitimate preview bots
	"telegrambot", "whatsapp", "signal",
	
	// Social platforms
	"twitterbot", "facebookexternalhit", "linkedinbot",
	
	// Communication platforms  
	"zulipbot", "rocket.chat", "mattermost",
}

// Check if a user agent is a legitimate social media bot
func isLegitimateBot(userAgent string) bool {
	if userAgent == "" {
		return false
	}

	lowerUA := strings.ToLower(userAgent)
	
	for _, legitBot := range legitimateSocialBots {
		if strings.Contains(lowerUA, legitBot) {
			return true
		}
	}
	
	return false
}

// Check if a user agent indicates a bot
func isBotUserAgent(userAgent string) bool {
	if userAgent == "" {
		return true // Empty user agent is suspicious
	}

	// First check if it's a legitimate social media bot
	if isLegitimateBot(userAgent) {
		return false // Allow legitimate social bots
	}

	lowerUA := strings.ToLower(userAgent)

	// Check exact matches first
	if knownBots[userAgent] {
		return true
	}

	// Check pattern matches
	for _, pattern := range botPatterns {
		if strings.Contains(lowerUA, pattern) {
			return true
		}
	}

	// Additional heuristics for bot detection
	if strings.Contains(lowerUA, "bot") ||
		strings.Contains(lowerUA, "crawl") ||
		strings.Contains(lowerUA, "spider") ||
		strings.Contains(lowerUA, "scrape") {
		return true
	}

	return false
}

// Add anti-indexing headers while preserving cacheability
func addAntiIndexHeaders(w http.ResponseWriter) {
	// Prevent indexing by search engines but allow caching
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, nosnippet, noarchive, noimageindex, notranslate, noydir, noods")
	
	// Additional meta robots directives
	w.Header().Set("Robots", "noindex, nofollow, noarchive, nosnippet, noimageindex")
	
	// Prevent AI training and content scraping
	w.Header().Set("X-No-AI-Training", "1")
	w.Header().Set("X-AI-Training", "prohibited")
}

// Serve robots.txt file
func getRobotsTxt(w http.ResponseWriter, r *http.Request) {
	robotsContent, err := os.ReadFile("robots.txt")
	if err != nil {
		// Fallback if robots.txt file doesn't exist
		fallbackRobots := `# Block all crawlers and bots
User-agent: *
Disallow: /
Crawl-delay: 86400

User-agent: GPTBot
Disallow: /

User-agent: ChatGPT-User
Disallow: /

User-agent: CCBot
Disallow: /

User-agent: Claude-Web
Disallow: /

User-agent: Google-Extended
Disallow: /`
		robotsContent = []byte(fallbackRobots)
	}

	w.Header().Set("Content-Type", "text/plain")
	addAntiIndexHeaders(w)
	w.Write(robotsContent)
}

// CDN content bot blocking middleware - only blocks bots from cached content  
func cdnBotBlockingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		query := r.URL.RawQuery
		filename := path + "?" + query
		
		// Allow root path requests through without bot blocking
		if filename == "/" || filename == "/?" {
			next(w, r)
			return
		}
		
		userAgent := r.Header.Get("User-Agent")
		clientIP := getClientIP(r)
		
		// Check IP blocklist for entire request chain (comprehensive)
		if blocked, blockedIP, source := isRequestBlocked(r); blocked {
			log.Printf("Blocked IP from CDN content - Blocked IP: %s (via %s), Client: %s, UA: %s, Path: %s", 
				blockedIP, source, clientIP, userAgent, r.URL.Path)
			
			recordIPBlock()
			
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access denied: IP address blocked"))
			stats.errors++
			return
		}
		
		// Check if it's a bot requesting CDN content
		if isBotUserAgent(userAgent) {
			// Log the blocked request
			log.Printf("Blocked bot from CDN content - UA: %s, IP: %s, Path: %s", 
				userAgent, clientIP, r.URL.Path)
			
			recordUABlock(userAgent)
			
			// Return 403 Forbidden for bots
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Access denied: Automated requests not permitted"))
			stats.errors++
			return
		}
		
		// Add anti-indexing headers for legitimate CDN requests
		addAntiIndexHeaders(w)
		
		// Track this request for rate monitoring
		trackRequest(clientIP, userAgent, r.URL.Path)
		
		// Continue to next handler for legitimate requests
		next(w, r)
	}
}