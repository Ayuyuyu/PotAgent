package server

// 本文件的 JSON 结构必须与 web/frontend/src/api/types.ts 保持一致。

type apiResult struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type sessionUser struct {
	Username  string `json:"username"`
	ExpiresIn int    `json:"expiresIn"`
}

type loginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type logEntry struct {
	ID            string                 `json:"id"`
	Timestamp     string                 `json:"timestamp"`
	EventCategory string                 `json:"eventCategory"`
	EventType     string                 `json:"eventType"`
	SrcIP         string                 `json:"srcIp"`
	DstIP         string                 `json:"dstIp"`
	IPProtocol    string                 `json:"ipProtocol"`
	SrcPort       uint16                 `json:"srcPort"`
	DstPort       uint16                 `json:"dstPort"`
	Details       map[string]interface{} `json:"details"`
}

type logTailResult struct {
	Entries     []logEntry `json:"entries"`
	Cursor      string     `json:"cursor"`
	Truncated   bool       `json:"truncated"`
	LogFileSize int64      `json:"logFileSize"`
	Matched     int        `json:"matched"`
}

type serviceItem struct {
	File        string  `json:"file"`
	Protocol    string  `json:"protocol"`
	Application string  `json:"application"`
	Host        string  `json:"host"`
	Port        uint16  `json:"port"`
	Enabled     bool    `json:"enabled"`
	Status      string  `json:"status"`
	Connections int     `json:"connections"`
	Events      int64   `json:"events"`
	LastEventAt *string `json:"lastEventAt"`
	StartedAt   *string `json:"startedAt"`
	LastError   string  `json:"lastError,omitempty"`
}

type enablePayload struct {
	Enabled bool `json:"enabled"`
}

type overviewStats struct {
	TotalEvents        int64   `json:"totalEvents"`
	TodayEvents        int64   `json:"todayEvents"`
	TodayDeltaPercent  float64 `json:"todayDeltaPercent"`
	UniqueSources      int64   `json:"uniqueSources"`
	UniqueSourcesDelta int     `json:"uniqueSourcesDelta"`
	ActiveServices     int     `json:"activeServices"`
	TotalServices      int     `json:"totalServices"`
	Connections        int     `json:"connections"`
	LogFileSize        int64   `json:"logFileSize"`
	LastLogAt          *string `json:"lastLogAt"`
	UptimeSeconds      int64   `json:"uptimeSeconds"`
}

type trendPoint struct {
	Label   string `json:"label"`
	At      string `json:"at"`
	Value   int64  `json:"value"`
	Sources int64  `json:"sources"`
}

type trendSeries struct {
	Range        string       `json:"range"`
	Points       []trendPoint `json:"points"`
	Total        int64        `json:"total"`
	DeltaPercent float64      `json:"deltaPercent"`
	PeakLabel    string       `json:"peakLabel"`
}

type topSource struct {
	IP        string `json:"ip"`
	Count     int64  `json:"count"`
	Location  string `json:"location"`
	Protocols int    `json:"protocols"`
	LastSeen  string `json:"lastSeen"`
}

type configFile struct {
	File        string `json:"file"`
	Protocol    string `json:"protocol"`
	Application string `json:"application"`
	Path        string `json:"path"`
	Content     string `json:"content"`
	Dirty       bool   `json:"dirty"`
	UpdatedAt   string `json:"updatedAt"`
}

type contentPayload struct {
	Content string `json:"content"`
}

type validationIssue struct {
	Level   string `json:"level"`
	Line    int    `json:"line"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

type validationResult struct {
	Valid     bool              `json:"valid"`
	Passed    int               `json:"passed"`
	Issues    []validationIssue `json:"issues"`
	CheckedAt string            `json:"checkedAt"`
}

type reloadResult struct {
	Reloaded   int    `json:"reloaded"`
	Failed     int    `json:"failed"`
	DurationMs int64  `json:"durationMs"`
	Message    string `json:"message"`
}
