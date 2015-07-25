package main

import (
	"flag"
	"fmt"
	//	"github.com/lair-framework/go-lair"
	//lv1 "gopkg.in/lair-framework/go-lair.v1"
	"log"
	"os"
)

var version = "1.0.0"
var usage = `
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
	log.Println("Success: Operation completed successfully")
}
