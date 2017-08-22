package aws

// User represents an AWS IAM user with its SSH keys.
// It implements the directory user interface.
type User struct {
	name    string
	sshKeys [][]byte
}

// ID returns the user identifier, the username usually.
func (u *User) ID() string {
	return u.name
}

// SSHKeys returns the user's SSH public keys in slices of bytes.
func (u *User) SSHKeys() [][]byte {
	return u.sshKeys
}
