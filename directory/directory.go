package directory

type Directory interface {
	ListGroupUsers(groupName string) ([]User, error)
}
