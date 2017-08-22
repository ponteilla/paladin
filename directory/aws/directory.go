package aws

import (
	"errors"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/ponteilla/paladin/directory"
)

// Directory is basically the AWS IAM API but with helper funcs.
type Directory struct {
	iamiface.IAMAPI
}

// NewDirectory return an IAM object.
func NewDirectory(sess *session.Session) directory.Directory {
	i := iam.New(sess)
	return &Directory{
		IAMAPI: i,
	}
}

// ListGroupUsers returns users of an IAM group.
func (d *Directory) ListGroupUsers(groupName string) ([]directory.User, error) {
	var users []directory.User

	ggInput := &iam.GetGroupInput{
		GroupName: aws.String(groupName),
	}
	ggOutput, err := d.IAMAPI.GetGroup(ggInput)
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

func userFromARN(dir *Directory, userName string) (directory.User, error) {
	lpkInput := &iam.ListSSHPublicKeysInput{
		UserName: aws.String(userName),
	}
	lpkOutput, err := dir.IAMAPI.ListSSHPublicKeys(lpkInput)
	if err != nil {
		return nil, err
	}

	var keys [][]byte
	for _, m := range lpkOutput.SSHPublicKeys {
		pkInput := &iam.GetSSHPublicKeyInput{
			UserName:       aws.String(userName),
			SSHPublicKeyId: m.SSHPublicKeyId,
			Encoding:       aws.String("SSH"),
		}

		pkOutput, err := dir.IAMAPI.GetSSHPublicKey(pkInput)
		if err != nil {
			continue
		}

		keys = append(keys, []byte(*pkOutput.SSHPublicKey.SSHPublicKeyBody))
	}

	if len(keys) == 0 {
		return nil, errors.New("no public keys")
	}

	return &User{
		name:    userName,
		sshKeys: keys,
	}, nil
}
