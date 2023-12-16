package inherite_scan

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/songzhibin97/go-baseutils/base/options"
)

type Probes []*Probe

func (p *Probes) Export(file string) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// 检查文件根路径是否存在,如果不存在则创建
	dir := filepath.Dir(file)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}
	// 检查文件是否存在,存在则报错
	if _, err := os.Stat(file); err == nil {
		return errors.New("file already exists")
	}
	// 创建文件
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func Load(file string) (Probes, error) {
	var p Probes
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &p)
	if err != nil {
		return nil, err
	}
	for _, probe := range p {
		for _, match := range probe.MatchList {
			err = match.Load()
			if err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}

type Scan struct {
	Probes  Probes `json:"probes"`
	config  *config
	mapping map[string]*Probe
}

type config struct {
	connTimeout time.Duration
	sendTimeout time.Duration
	readTimeout time.Duration

	useAllProbe      bool
	useNULLProbeOnly bool
	sslAlwaysTry     bool

	rarity int
}

func SetConnTimeout(connTimeout time.Duration) options.Option[*config] {
	return func(o *config) {
		o.connTimeout = connTimeout
	}
}

func SetSendTimeout(sendTimeout time.Duration) options.Option[*config] {
	return func(o *config) {
		o.sendTimeout = sendTimeout
	}
}

func SetReadTimeout(readTimeout time.Duration) options.Option[*config] {
	return func(o *config) {
		o.readTimeout = readTimeout
	}
}

func SetUseAllProbe(useAllProbe bool) options.Option[*config] {
	return func(o *config) {
		o.useAllProbe = useAllProbe
	}
}

func SetSSLAlwaysTry(sslAlwaysTry bool) options.Option[*config] {
	return func(o *config) {
		o.sslAlwaysTry = sslAlwaysTry
	}
}

func SetRarity(rarity int) options.Option[*config] {
	return func(o *config) {
		o.rarity = rarity
	}
}

func (t *Scan) Scan(target Target) (*Result, error) {
	var probesUsed []*Probe
	if t.config.useAllProbe {
		for _, probe := range t.Probes {
			if strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) {
				probesUsed = append(probesUsed, probe)
			}
		}
	} else if !t.config.useAllProbe && t.config.useNULLProbeOnly {
		probesUsed = append(probesUsed, t.mapping["NULL"])
	} else {
		for _, probe := range t.Probes {
			if strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) && (probe.InPort(target.Port) || probe.InSSLPort(target.Port)) {
				probesUsed = append(probesUsed, probe)
			}
		}
		probesUsed = append(probesUsed, t.mapping["NULL"])
	}

	var filterProbesUsed []*Probe
	for i, probe := range probesUsed {
		if probe.Rarity > t.config.rarity {
			continue
		}
		filterProbesUsed = append(filterProbesUsed, probesUsed[i])
	}

	if len(filterProbesUsed) == 0 {
		return nil, errors.New("no probes used")
	}

	return t.scan(target, filterProbesUsed)
}

func (t *Scan) scan(target Target, filterProbesUsed []*Probe) (*Result, error) {
	for _, probe := range filterProbesUsed {
		var response []byte
		var ssl bool
		payload, _ := DecodeData(probe.Payload)
		if probe.InSSLPort(target.Port) {
			response, ssl, _ = t.request(target, true, payload)
		} else {
			var err error
			response, ssl, err = t.request(target, false, payload)
			if err != nil && t.config.sslAlwaysTry {
				response, ssl, _ = t.request(target, true, payload)
			}
		}
		if len(response) > 0 {
			var softFound bool
			var softMatch *Match

			for _, m := range probe.MatchList {
				isMatch := m.MatchPattern(response)
				if isMatch && !m.IsSoft {
					return newResult(target, probe, response, ssl, m), nil
				} else if isMatch && m.IsSoft && !softFound {
					softFound = true
					softMatch = m
				}
			}

			fbProbe, ok := t.mapping[probe.Fallback]
			if ok {
				for _, m := range fbProbe.MatchList {
					isMatch := m.MatchPattern(response)
					if isMatch && !m.IsSoft {
						return newResult(target, probe, response, ssl, m), nil
					} else if isMatch && m.IsSoft && !softFound {
						softFound = true
						softMatch = m
					}
				}
			}
			return newResult(target, probe, response, ssl, softMatch), nil
		}
	}

	return nil, errors.New("no valid service is identified")
}

func newResult(target Target, probe *Probe, response []byte, ssl bool, match *Match) *Result {
	r := &Result{
		Target: target,
		Service: Service{
			Target:      target,
			Name:        "unknown",
			Protocol:    strings.ToLower(probe.Protocol),
			Banner:      string(response),
			BannerBytes: response,
			IsSSL:       ssl,
			Details: Details{
				ProbeName: probe.Directive.DirectiveName,
				ProbeData: probe.Payload,
			},
		},
		Timestamp: time.Now().Unix(),
	}

	if match != nil {
		r.Extras = match.ParseVersionInfo(response)
		r.Details.MatchMatched = match.Pattern
		r.Details.IsSoftMatched = match.IsSoft
		r.Service.Name = match.Service
	}

	return r
}

func (t *Scan) request(target Target, ssl bool, data []byte) ([]byte, bool, error) {
	dialer := net.Dialer{
		KeepAlive: -1,
	}
	if !(target.Protocol == "tcp" || target.Protocol == "udp") {
		return nil, ssl, errors.New("protocol must be either tcp or udp")
	}
	tx, cancel := context.WithTimeout(context.Background(), t.config.connTimeout)
	defer cancel()
	conn, err := dialer.DialContext(tx, target.Protocol, target.GetAddress())
	if err != nil {
		return nil, ssl, err
	}
	if ssl {
		conn = tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
	}
	defer conn.Close()
	if data != nil {
		err = conn.SetWriteDeadline(time.Now().Add(t.config.sendTimeout))
		if err != nil {
			return nil, ssl, err
		}
		_, err = conn.Write(data)
		if err != nil {
			return nil, ssl, err
		}
	}

	err = conn.SetReadDeadline(time.Now().Add(t.config.readTimeout))
	if err != nil {
		return nil, ssl, err
	}
	buff := make([]byte, 1024)
	n, err := io.ReadAtLeast(conn, buff, 1)
	if err != nil {
		return nil, ssl, err
	}
	return buff[:n], ssl, nil
}

func NewScan(probes Probes, options ...options.Option[*config]) *Scan {
	mapping := make(map[string]*Probe, len(probes))
	for i, probe := range probes {
		mapping[probe.Directive.DirectiveName] = probes[i]
	}

	c := &config{
		connTimeout:  10 * time.Second,
		sendTimeout:  10 * time.Second,
		readTimeout:  10 * time.Second,
		useAllProbe:  false,
		sslAlwaysTry: false,
		rarity:       10,
	}

	for _, o := range options {
		o(c)
	}

	return &Scan{
		Probes:  probes,
		config:  c,
		mapping: mapping,
	}
}
