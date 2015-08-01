package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/lair-framework/go-lair"
	lv1 "gopkg.in/lair-framework/go-lair.v1"
)

const (
	version = "1.0.0"
	tool    = "rawv1"
	usage   = `
Usage:
  drone-raw-v1 <id> <filename>
  export LAIR_ID=<id>; drone-raw-v1 <filename>
Options:
  -v              show version and exit
  -h              show usage and exit
  -k              allow insecure SSL connections
  -force-ports    disable data protection in the API server for excessive ports
  -tags           a comma separated list of tags to add to every host that is imported
`
)

func main() {
	showVersion := flag.Bool("v", false, "")
	insecureSSL := flag.Bool("k", false, "")
	forcePorts := flag.Bool("force-ports", false, "")
	tags := flag.String("tags", "", "")
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	if *showVersion {
		log.Println(version)
		os.Exit(0)
	}
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	lairPID := os.Getenv("LAIR_ID")
	var filename string
	switch len(flag.Args()) {
	case 2:
		lairPID = flag.Arg(0)
		filename = flag.Arg(1)
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}
	log.Println(lairPID, filename, *insecureSSL, *forcePorts, *tags)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Fatal: Could not open file. Error %s", err.Error())
	}
	hostTags := strings.Split(*tags, ",")
	l1 := lv1.Project{}
	if err := json.Unmarshal(data, l1); err != nil {
		log.Fatalf("Fatal: Could not parse JSON. Error %s", err.Error())
	}
	l2 := lair.Project{
		CreatedAt: l1.CreationDate,
		DroneLog:  l1.DroneLog,
		Tool:      tool,
	}
	for _, h := range l1.Hosts {
		l2Host := lair.Host{
			Status:         h.Status,
			LongIPv4Addr:   h.LongAddr,
			IPv4:           h.StringAddr,
			MAC:            h.MacAddr,
			IsFlagged:      h.Flag,
			Hostnames:      h.Hostnames,
			Tags:           hostTags,
			LastModifiedBy: h.LastModifiedBy,
		}
		for _, o := range h.OS {
			if o.Weight > l2Host.OS.Weight {
				l2Host.OS.Weight = o.Weight
				l2Host.OS.Fingerprint = o.Fingerprint
				l2Host.OS.Tool = o.Tool
			}
		}
		for _, n := range h.Notes {
			l2Host.Notes = append(l2Host.Notes, lair.Note{
				Title:   n.Title,
				Content: n.Content,
			})
		}
		for _, p := range h.Ports {
			l2Service := lair.Service{
				IsFlagged:      p.Flag,
				Status:         p.Status,
				Port:           p.Port,
				Service:        p.Service,
				Protocol:       p.Protocol,
				LastModifiedBy: p.LastModifiedBy,
			}
			for _, c := range p.Credentials {
				l2Credential := lair.Credential{
					Hash:     c.Hash,
					Password: c.Password,
					Username: c.Username,
					Host:     h.StringAddr,
					Service:  strconv.Itoa(p.Port),
				}
				l2.Credentials = append(l2.Credentials, l2Credential)
			}
			for _, n := range p.Notes {
				l2Service.Notes = append(l2Service.Notes, lair.Note{
					Title:   n.Title,
					Content: n.Content,
				})
			}
			l2Host.Services = append(l2Host.Services, l2Service)
		}
		l2.Hosts = append(l2.Hosts, l2Host)
	}
	for _, n := range l1.Notes {
		l2.Notes = append(l2.Notes, lair.Note{
			Title:   n.Title,
			Content: n.Content,
		})
	}
	for _, c := range l1.Commands {
		l2.Commands = append(l2.Commands, lair.Command{
			Command: c.Command,
			Tool:    c.Tool,
		})
	}
	for _, v := range l1.Vulnerabilities {
		l2Issue := lair.Issue{
			Title:          v.Title,
			Status:         v.Status,
			IsConfirmed:    v.Confirmed,
			CVEs:           v.Cves,
			CVSS:           v.Cvss,
			Description:    v.Description,
			Evidence:       v.Evidence,
			Solution:       v.Solution,
			IsFlagged:      v.Flag,
			IdentifiedBy:   v.IdentifiedBy,
			LastModifiedBy: v.LastModifiedBy,
		}
		for _, h := range v.Hosts {
			l2Issue.Hosts = append(l2Issue.Hosts, lair.IssueHost{
				IPv4:     h.StringAddr,
				Port:     h.Port,
				Protocol: h.Protocol,
			})
		}
		for _, n := range v.Notes {
			l2Issue.Notes = append(l2Issue.Notes, lair.Note{
				Title:   n.Title,
				Content: n.Content,
			})
		}
		for _, p := range v.PluginIds {
			l2Issue.PluginIDs = append(l2Issue.PluginIDs, lair.PluginID{
				ID:   p.Id,
				Tool: p.Tool,
			})
		}
	}
	log.Println("Success: Operation completed successfully")
}
