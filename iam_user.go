package main

import (
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
)

// IAMUser represents an AWS IAM user with its SSH keys.
type IAMUser struct {
	Name    string
	SSHKeys [][]byte
}

// NewIAMUser returns an IAM user.
// It hashes the user keys for signature/caching purposes.
func NewIAMUser(name string, keys [][]byte) *IAMUser {
	return &IAMUser{
		Name:    name,
		SSHKeys: keys,
	}
}

func userFromARN(dir *IAM, userName string) (*IAMUser, error) {
	lpkInput := &iam.ListSSHPublicKeysInput{
		UserName: aws.String(userName),
	}
	lpkOutput, err := dir.iam.ListSSHPublicKeys(lpkInput)
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

		pkOutput, err := dir.iam.GetSSHPublicKey(pkInput)
		if err != nil {
			continue
		}

		keys = append(keys, []byte(*pkOutput.SSHPublicKey.SSHPublicKeyBody))
	}

	if len(keys) == 0 {
		return nil, errors.New("no public keys")
	}

	return NewIAMUser(userName, keys), nil
}
