// +build linux darwin

package os

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	osuser "os/user"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/ponteilla/paladin/directory"
)

// UsersGobPath is the path at which to store users.
const UsersGobPath = "/var/lib/paladin.gob"

// Controller carries Linux users and provides ways to interact with them.
// Not safe to use by multiple goroutines.
// TODO: improve/move storage
type Controller struct {
	users      map[string]directory.User
	cmdAddUser func(name string) error
}

// NewOSController returns a Linux controller to manage users.
// It also tries to turn on sudo for members of the wheel group.
func NewOSController() ControllerInterface {
	lc := &Controller{
		users: make(map[string]directory.User),
	}

	b, err := ioutil.ReadFile("/etc/sudoers")
	if err != nil {
		log.Fatal("unable to read sudoers file")
	}
	re := regexp.MustCompile("# (%wheel\\s+ALL=\\(ALL\\)\\s+NOPASSWD: ALL)")
	sudoers := re.ReplaceAllString(string(b), "$1")
	if err = ioutil.WriteFile("/etc/sudoers", []byte(sudoers), 0); err != nil {
		log.Fatal("unable to write sudoers files")
	}

	fp, err := os.Open("/etc/os-release")
	if err != nil {
		log.Fatal("unable to print os-release")
	}

	b, err = ioutil.ReadAll(fp)
	if err != nil {
		log.Fatal("unable to read all os-release")
	}

	if strings.Contains(string(b), "ubuntu") {
		lc.cmdAddUser = func(name string) error {
			cmd := exec.Command("adduser", "--disabled-password", "-G", "wheel", name)
			_, err := cmd.Output()
			if err != nil {
				return err
			}

			return nil
		}
	} else {
		lc.cmdAddUser = func(name string) error {
			cmd := exec.Command("useradd", "-G", "wheel", name)

			_, err := cmd.Output()
			if err != nil {
				return err
			}

			return nil
		}
	}

	lc.loadUsers()
	return lc
}

func (r *Controller) addUser(user directory.User) error {
	if _, ok := r.users[user.ID()]; ok {
		return errors.New("user already exists")
	}

	if err := r.cmdAddUser(user.ID()); err != nil {
		return err
	}

	if err := writeUserSSHKeys(user); err != nil {
		return err
	}

	r.users[user.ID()] = user
	return nil
}

func (r *Controller) removeUser(user directory.User) error {
	if _, ok := r.users[user.ID()]; !ok {
		return errors.New("user does not exist")
	}

	cmd := exec.Command("userdel", "--remove", user.ID())
	if err := cmd.Run(); err != nil {
		return err
	}

	delete(r.users, user.ID())
	return nil
}

func (r *Controller) dumpUsers() error {
	fp, err := os.OpenFile(UsersGobPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		// log.Fatalf("unable to open file %s: %v", UsersGobPath, err)
		return err
	}
	defer fp.Close()

	enc := gob.NewEncoder(fp)
	if err := enc.Encode(r.users); err != nil {
		// log.Fatalf("unable to encode users to gobs: %v", err)
		return err
	}

	return nil
}

func (r *Controller) loadUsers() error {
	fp, err := os.Open(UsersGobPath)
	if err != nil {
		return err
	}
	defer fp.Close()

	dec := gob.NewDecoder(fp)
	if err := dec.Decode(&r.users); err != nil {
		log.Fatalf("unable to decode users from gobs: %v", err)
	}
	return nil
}

// ApplyUsers compares the input users with what is has in memory and
// adds/removes/updates them accordingly.
func (r *Controller) ApplyUsers(users []directory.User) error {
	diff := make(map[string]directory.User)

	for _, u := range users {
		diff[u.ID()] = u
		if _, ok := r.users[u.ID()]; !ok {
			if err := r.addUser(u); err != nil {
				log.Fatalf("unable to add user %s: %v", u.ID(), err)
				// return err
			}
			log.Printf("added user: %s", u.ID())
			continue
		}

		if !reflect.DeepEqual(r.users[u.ID()].SSHKeys(), u.SSHKeys()) {
			if err := writeUserSSHKeys(u); err != nil {
				log.Fatalf("unable to amend user %s ssh keys: %v", u.ID(), err)
				// return err
			}
			log.Printf("updated user: %s", u.ID())
		}
	}

	for n, u := range r.users {
		if _, ok := diff[n]; !ok {
			if err := r.removeUser(u); err != nil {
				log.Fatalf("unable to remove user %s: %v", u.ID(), err)
				// return err
			}
			log.Printf("removed user: %s", u.ID())
		}
	}

	r.dumpUsers()

	return nil
}

func writeUserSSHKeys(user directory.User) error {
	lUser, err := osuser.Lookup(user.ID())
	if err != nil {
		return err
	}

	sshConfigPath := fmt.Sprintf("%s/.ssh", lUser.HomeDir)

	if err = os.MkdirAll(lUser.HomeDir+"/.ssh", 0700); err != nil {
		return err
	}

	fp, err := os.OpenFile(sshConfigPath+"/authorized_keys", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer fp.Close()

	for _, key := range user.SSHKeys() {
		fp.Write(key)
		fp.WriteString("\n")
	}

	uid, _ := strconv.Atoi(lUser.Uid)
	gid, _ := strconv.Atoi(lUser.Gid)
	if err = os.Chown(sshConfigPath, uid, gid); err != nil {
		return err
	}
	if err = fp.Chown(uid, gid); err != nil {
		return err
	}

	return nil
}
