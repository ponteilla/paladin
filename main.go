package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
)

var (
	groupName string
	interval  int
)

func init() {
	flag.StringVar(&groupName, "groupname", "", "IAM group name to look for users")
	flag.IntVar(&interval, "interval", 900, "IAM polling interval")
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

	for {
		users, err := dir.ListGroupUsers(groupName)
		if err != nil {
			log.Fatalf("unable to list group users: %v\n", err)
		}

		ctrl.ApplyUsers(users)
		time.Sleep(time.Second * time.Duration(interval))
	}
}
