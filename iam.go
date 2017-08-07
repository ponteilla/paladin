package main

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

// IAM is basically the AWS IAM API but with helper funcs.
type IAM struct {
	iam iamiface.IAMAPI
}

// NewIAM return an IAM object.
func NewIAM(sess *session.Session) *IAM {
	iam := iam.New(sess)
	return &IAM{
		iam: iam,
	}
}

// ListGroupUsers returns users of an IAM group.
func (d *IAM) ListGroupUsers(groupName string) ([]*IAMUser, error) {
	var users []*IAMUser

	ggInput := &iam.GetGroupInput{
		GroupName: aws.String(groupName),
	}
	ggOutput, err := d.iam.GetGroup(ggInput)
	if err != nil {
		return nil, err
	}

	for _, u := range ggOutput.Users {
		a, err := userFromARN(d, *u.UserName)
		if err != nil {
			log.Printf("skipping user %s: %v", *u.UserName, err)
			continue
		}
		users = append(users, a)
	}

	return users, nil
}
