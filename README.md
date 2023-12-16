# inheritance_scan

## nmap-service-probes 下载
```shell
wget https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes
```

## 解析依赖
```go
package main

import "github.com/songzhibin97/inheritance_scan/parser"

func main() {
	p := parser.NewParse("./nmap-service-probes")
	probes, err := p.ParserProbes()
	if err != nil {
		panic(err)
	}
	probes.Export("./nmap-service-probes.json")
}
```

## 测试扫描

```go
package main

import (
	"fmt"
	"github.com/songzhibin97/inheritance_scan"
)

func main() {
	probes, err := inherite_scan.Load("./nmap-service-probes.json")
	if err != nil {
		panic(err)
	}

	scan := inherite_scan.NewScan(probes)
	result, err := scan.Scan(inherite_scan.Target{
		IP:       "127.0.0.1",
		Port:     5432,
		Protocol: "tcp",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(result)
}

```