package os

import "github.com/ponteilla/paladin/directory"

// ControllerInterface is an interface for something that manages users in a
// running system. It can an OS but a running software such a datastore.
type ControllerInterface interface {
	ApplyUsers([]directory.User) error
}
