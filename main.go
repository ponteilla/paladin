package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
)

var (
	groupName string
	interval  int
)

func init() {
	flag.StringVar(&groupName, "groupname", "", "IAM group name to look for users")
	flag.IntVar(&interval, "interval", 900, "IAM polling interval in seconds")
}

func main() {
	flag.Parse()
	if groupName == "" {
		flag.Usage()
		os.Exit(1)
	}

	ctrl := NewLinuxController()
	sess := session.Must(session.NewSession())
	dir := NewIAM(sess)

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	tick := time.Tick(time.Second * time.Duration(interval))
	for {
		select {
		case <-ch:
			return
		case <-tick:
			users, err := dir.ListGroupUsers(groupName)
			if err != nil {
				log.Fatalf("unable to list group users: %v", err)
			}
			ctrl.ApplyUsers(users)
		}
	}
}
