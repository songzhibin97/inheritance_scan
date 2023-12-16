package inherite_scan

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

type Target struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (t *Target) GetAddress() string {
	return net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
}

type Service struct {
	Target

	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Banner      string `json:"banner"`
	BannerBytes []byte `json:"banner_bytes"`

	IsSSL bool `json:"is_ssl"`

	Extras  `json:"extras"`
	Details `json:"details"`
}

type Extras struct {
	VendorProduct   string `json:"vendor_product,omitempty"`
	Version         string `json:"version,omitempty"`
	Info            string `json:"info,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	OperatingSystem string `json:"operating_system,omitempty"`
	DeviceType      string `json:"device_type,omitempty"`
	CPE             string `json:"cpe,omitempty"`
}

type Details struct {
	ProbeName     string `json:"probe_name"`
	ProbeData     string `json:"probe_data"`
	MatchMatched  string `json:"match_matched"`
	IsSoftMatched bool   `json:"soft_matched"`
}

type Result struct {
	Target
	Service `json:"service"`

	Timestamp int64  `json:"timestamp"`
	Error     string `json:"error"`
}

type Match struct {
	IsSoft bool `json:"is_soft"`

	Service     string `json:"service"`
	Pattern     string `json:"pattern"`
	VersionInfo string `json:"version_info"`

	PatternCompiled     *regexp.Regexp `json:"-"`
	PatternUnescapedStr string
}

func (m *Match) Load() error {
	var err error
	if m.PatternCompiled == nil {
		m.PatternCompiled, err = regexp.Compile(m.PatternUnescapedStr)
		return err
	}
	return nil
}

func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	// 匹配结果大于 0 表示规则与 response 匹配成功
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	versionInfo := m.VersionInfo
	foundItems = foundItems[1:]
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}

type Probe struct {
	Directive *Directive `json:"directive"`
	Payload   string     `json:"payload"`
	Protocol  string     `json:"protocol"`

	Ports    []int `json:"ports"`
	SSLPorts []int `json:"ssl_ports"`

	TotalWaitMS  int    `json:"total_wait_ms"`
	TCPWrappedMS int    `json:"tcp_wrapped_ms"`
	Rarity       int    `json:"rarity"`
	Fallback     string `json:"fallback"`

	MatchList []*Match `json:"match_list"`
}

func (p *Probe) InPort(port int) bool {
	for _, v := range p.Ports {
		if port == v {
			return true
		}
	}
	return false
}

func (p *Probe) InSSLPort(port int) bool {
	for _, v := range p.SSLPorts {
		if port == v {
			return true
		}
	}
	return false
}

type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

/*
解析 nmap-service-probes 中匹配规则字符串，转换成 golang 中可以进行编译的字符串

	  e.g.
		(1) pattern: \0\xffHi
			decoded: []byte{0, 255, 72, 105} 4len

		(2) pattern: \\0\\xffHI
			decoded: []byte{92, 0, 92, 120, 102, 102, 72, 105} 8len

		(3) pattern: \x2e\x2a\x3f\x2b\x7b\x7d\x28\x29\x5e\x24\x7c\x5c
			decodedStr: \.\*\?\+\{\}\(\)\^\$\|\\
*/

func DecodePattern(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		// 十六进制转义格式
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
			//fmt.Println("match:", match, "replace:", replace)
		}
		// 格式控制符 \r\n\a\b\f\t
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		// 十六进制转义格式
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		// 格式控制符 \r\n\a\b\f\t
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}
