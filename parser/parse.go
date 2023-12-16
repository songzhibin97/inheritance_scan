package parser

import (
	"errors"
	"os"
	"strconv"
	"strings"

	inherite_scan "github.com/songzhibin97/inheritance_scan"
)

type Parse struct {
	filePath string
}

func NewParse(filePath string) *Parse {
	return &Parse{
		filePath: filePath,
	}
}

func (p *Parse) ParserProbes() (inherite_scan.Probes, error) {

	fileString, err := os.ReadFile(p.filePath)
	if err != nil {
		return nil, err
	}
	content := string(fileString)

	var probes []*inherite_scan.Probe

	var lines []string
	// 过滤掉规则文件中的注释和空行
	linesTemp := strings.Split(content, "\n")
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}
	// 判断第一行是否为 "Exclude " 设置
	if len(lines) == 0 {
		return nil, errors.New("parse error on nmap-service-probes file: no content")
	}
	c := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			c += 1
		}
		// 一份规则文件中有且至多有一个 Exclude 设置
		if c > 1 {
			return nil, errors.New("only 1 Exclude directive is allowed in the nmap-service-probes file")
		}
	}
	l := lines[0]
	if !(strings.HasPrefix(l, "Exclude ") || strings.HasPrefix(l, "Probe ")) {
		return nil, errors.New("parse error on nmap-service-probes file: line was expected to begin with \"Probe \" or \"Exclude \"")
	}
	if c == 1 {
		lines = lines[1:]
	}
	content = strings.Join(lines, "\n")
	content = "\n" + content

	// 按 "\nProbe" 拆分探针组内容
	probeParts := strings.Split(content, "\nProbe")
	probeParts = probeParts[1:]

	for _, probePart := range probeParts {
		probe, err := p.parserProbe(probePart)
		if err != nil {
			return nil, err
		}
		probes = append(probes, probe)
	}
	return probes, nil
}

func (p *Parse) parserProbeInfo(content string) (*inherite_scan.Directive, string, error) {
	if len(content) < 4 {
		return nil, "", errors.New("content length must be greater than 4")
	}

	proto := content[:4]
	other := content[4:]

	if !(proto == "TCP " || proto == "UDP ") {
		return nil, "", errors.New("protocol must be TCP or UDP")
	}
	if len(other) == 0 {
		return nil, "", errors.New("other content is empty")
	}
	directive := p.parserDirective(other)
	return directive, strings.ToLower(strings.TrimSpace(proto)), nil
}

func (p *Parse) parserDirective(context string) *inherite_scan.Directive {
	if strings.Count(context, " ") <= 0 {
		panic("nmap-service-probes - error directive format")
	}
	blankIndex := strings.Index(context, " ")

	return &inherite_scan.Directive{
		DirectiveName: context[:blankIndex],
		Flag:          context[blankIndex+1 : blankIndex+2],
		Delimiter:     context[blankIndex+2 : blankIndex+3],
		DirectiveStr:  context[blankIndex+3:],
	}
}

func (p *Parse) parseMatch(data string) (match *inherite_scan.Match, err error) {

	matchText := data[len("match")+1:]
	directive := p.parserDirective(matchText)

	textSplit := strings.Split(directive.DirectiveStr, directive.Delimiter)
	pattern, versionInfo := textSplit[0], strings.Join(textSplit[1:], "")
	patternUnescaped, _ := inherite_scan.DecodePattern(pattern)

	match = &inherite_scan.Match{
		Service:             directive.DirectiveName,
		Pattern:             pattern,
		VersionInfo:         versionInfo,
		PatternUnescapedStr: string([]rune(string(patternUnescaped))),
	}

	err = match.Load()
	if err != nil {
		return match, err
	}

	return match, nil
}

func (p *Parse) parseSoftMatch(data string) (match *inherite_scan.Match, err error) {
	matchText := data[len("softmatch")+1:]
	directive := p.parserDirective(matchText)
	textSplit := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplit[0], strings.Join(textSplit[1:], "")
	patternUnescaped, _ := inherite_scan.DecodePattern(pattern)

	match = &inherite_scan.Match{
		IsSoft:              true,
		Service:             directive.DirectiveName,
		Pattern:             pattern,
		VersionInfo:         versionInfo,
		PatternUnescapedStr: string([]rune(string(patternUnescaped))),
	}

	err = match.Load()
	if err != nil {
		return match, err
	}

	return match, nil
}

func (p *Parse) parserProbe(data string) (*inherite_scan.Probe, error) {

	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")

	directive, proto, err := p.parserProbeInfo(lines[0])
	if err != nil {
		return nil, err
	}

	probe := inherite_scan.Probe{
		Directive: directive,
		Protocol:  proto,
		Payload:   strings.Split(directive.DirectiveStr, directive.Delimiter)[0],
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.parseMatch(line)
			if err != nil {
				continue
			}
			probe.MatchList = append(probe.MatchList, match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.parseSoftMatch(line)
			if err != nil {
				continue
			}
			probe.MatchList = append(probe.MatchList, softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			probe.Ports, _ = parsePorts(line[len("ports")+1:])
		} else if strings.HasPrefix(line, "sslports ") {
			probe.SSLPorts, _ = parsePorts(line[len("sslports")+1:])
		} else if strings.HasPrefix(line, "totalwaitms ") {
			probe.TotalWaitMS, _ = strconv.Atoi(string(line[len("totalwaitms")+1:]))
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			probe.TCPWrappedMS, _ = strconv.Atoi(string(line[len("tcpwrappedms")+1:]))
		} else if strings.HasPrefix(line, "rarity ") {
			probe.Rarity, _ = strconv.Atoi(string(line[len("rarity")+1:]))
		} else if strings.HasPrefix(line, "fallback ") {
			probe.Fallback = line[len("fallback")+1:]
		}
	}

	return &probe, nil
}

func parsePorts(lines string) ([]int, error) {
	var ports []int
	for _, s := range strings.Split(lines, ",") {
		if strings.Contains(s, "-") {
			sp := strings.Split(s, "-")
			if len(sp) != 2 {
				return nil, errors.New("invalid port range")
			}
			start, err := strconv.Atoi(sp[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(sp[1])
			if err != nil {
				return nil, err
			}
			for start < end {
				ports = append(ports, start)
				start++
			}
		} else {
			p, err := strconv.Atoi(s)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}
