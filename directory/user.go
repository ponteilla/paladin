package directory

type User interface {
	ID() string
	SSHKeys() [][]byte
}
