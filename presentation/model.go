package presentation

var (
	Out        *Output = &Output{}
	outputFile         = "out.json"
)

type Result struct {
	Message   string        `json:"message"`
	Resources []interface{} `json:"resources"`
	Info      string        `json:"info"`
	Caveat    string        `json:"caveat"`
}

type CheckOutput struct {
	CheckName     string   `json:"check_name"`
	CheckType     string   `json:"check_type"`
	CheckCategory string   `json:"check_category"`
	Errors        bool     `json:"errors"`
	ErrorList     []string `json:"error_list"`
	Issues        bool     `json:"issues"`
	Result        Result   `json:"result"`
}

type Output struct {
	ServerIP       string        `json:"server_ip"`
	ServerPort     int           `json:"server_port"`
	Sid            string        `json:"sid"`
	ExecutedChecks []string      `json:"executed_checks"`
	SkippedChecks  []string      `json:"skipped_checks"`
	Checks         []CheckOutput `json:"checks"`
	Categories     []string
}
