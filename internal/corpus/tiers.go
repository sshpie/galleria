package corpus

// Tier defines a priority group for batched probing.
type Tier struct {
	Name       string
	Priority   int // lower = higher priority
	Categories []string
}

// DefaultTiers returns the standard probe priority order.
var DefaultTiers = []Tier{
	{
		Name:     "ai-inference",
		Priority: 1,
		Categories: []string{
			"ai_inference", "llm", "model_server", "embedding",
			"vector_db", "voice_ai", "tts", "stt", "asr",
			"ai_agent", "agent_framework", "rag",
		},
	},
	{
		Name:     "ml-platform",
		Priority: 2,
		Categories: []string{
			"ml_platform", "mlops", "training", "fine_tuning",
			"ai_gateway", "ai_security", "guardrails",
			"monitoring", "observability", "tracing",
		},
	},
	{
		Name:     "data-infra",
		Priority: 3,
		Categories: []string{
			"database", "time_series_db", "search_engine",
			"message_queue", "streaming", "storage", "cache",
			"graph_db", "document_db", "coordination",
		},
	},
	{
		Name:     "ics-scada",
		Priority: 4,
		Categories: []string{
			"ics", "scada", "ot", "plc", "industrial",
		},
	},
}

// ICSPorts are standard ICS/SCADA ports that get binary probes regardless of floor.
var ICSPorts = []int{
	102,  // S7 (Siemens)
	502,  // Modbus
	2404, // IEC-60870-5-104
	4840, // OPC-UA
	9600, // OMRON FINS
	20000, // DNP3
	44818, // EtherNet/IP
	47808, // BACnet
}

// BinaryProtocolPorts are ports that speak non-HTTP protocols and bypass floor matching.
var BinaryProtocolPorts = map[int]string{
	6379:  "redis",
	6380:  "redis",
	11211: "memcached",
	5672:  "rabbitmq-amqp",
	9092:  "kafka",
	9094:  "kafka",
	27017: "mongodb",
	5432:  "postgresql",
	3306:  "mysql",
	1883:  "mqtt",
	8883:  "mqtt-tls",
	502:   "modbus",
	102:   "s7-siemens",
	2404:  "iec104",
}

// TierForPort returns the tier name for a given port based on corpus matches.
// Returns "unknown" if no corpus match found.
func TierForPort(port int) string {
	matches := MatchPort(port)
	if len(matches) == 0 {
		return "unknown"
	}
	// Find the highest-priority tier containing this platform's category.
	bestPriority := 999
	bestTier := "unknown"
	for _, plat := range matches {
		for _, tier := range DefaultTiers {
			for _, cat := range tier.Categories {
				if cat == plat.Category {
					if tier.Priority < bestPriority {
						bestPriority = tier.Priority
						bestTier = tier.Name
					}
				}
			}
		}
	}
	return bestTier
}

// GroupPortsByTier partitions a port list into tier buckets.
// Ports with no corpus match go into "unknown".
// Binary protocol ports are always in their own bucket regardless of tier.
func GroupPortsByTier(ports []int) map[string][]int {
	groups := make(map[string][]int)
	for _, port := range ports {
		if _, isBinary := BinaryProtocolPorts[port]; isBinary {
			groups["binary"] = append(groups["binary"], port)
			continue
		}
		tier := TierForPort(port)
		groups[tier] = append(groups[tier], port)
	}
	return groups
}
