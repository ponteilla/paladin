package directory

type Directory interface {
	ListGroupUsers(groupNames ...string) ([]User, error)
}
