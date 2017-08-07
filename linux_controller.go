package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	osuser "os/user"
	"regexp"
	"strconv"
	"strings"
)

// LinuxController carries Linux users and provides ways to interact with them.
// Not safe to use by multiple goroutines.
// TODO: improve/move storage
type LinuxController struct {
	users      map[string]*IAMUser
	cmdAdduser func(name string) error
}

// NewLinuxController returns a Linux controller to manage users.
// It also tries to turn on sudo for members of the wheel group.
func NewLinuxController() *LinuxController {
	lc := &LinuxController{
		users: make(map[string]*IAMUser),
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
		lc.cmdAdduser = func(name string) error {
			cmd := exec.Command("adduser", "--disabled-password", "-G", "wheel", name)
			return cmd.Run()
		}
	} else {
		lc.cmdAdduser = func(name string) error {
			cmd := exec.Command("adduser", "-G", "wheel", name)
			return cmd.Run()
		}
	}

	return lc
}

func (r *LinuxController) addUser(user *IAMUser) error {
	if _, ok := r.users[user.Name]; ok {
		return errors.New("user already exists")
	}

	if err := r.cmdAdduser(user.Name); err != nil {
		return err
	}

	if err := writeUserSSHKeys(user); err != nil {
		return err
	}

	r.users[user.Name] = user

	log.Printf("added user %s to access control\n", user.Name)
	return nil
}

func (r *LinuxController) removeUser(user *IAMUser) error {
	if _, ok := r.users[user.Name]; !ok {
		return errors.New("user does not exist")
	}

	cmd := exec.Command("userdel", "--remove", user.Name)
	if err := cmd.Run(); err != nil {
		return err
	}

	delete(r.users, user.Name)

	log.Printf("removed user %s from access control\n", user.Name)
	return nil
}

// ApplyUsers compares the input users with what is has in memory and
// adds/removes/updates them accordingly.
func (r *LinuxController) ApplyUsers(users []*IAMUser) error {
	userMap := make(map[string]*IAMUser)
	for _, u := range users {
		userMap[u.Name] = u
		if _, ok := r.users[u.Name]; !ok {
			if err := r.addUser(u); err != nil {
				log.Fatalf("unable to add user %s: %v\n", u.Name, err)
			}

			if bytes.Compare(r.users[u.Name].SKHash, u.SKHash) != 0 {
				if err := writeUserSSHKeys(u); err != nil {
					log.Fatalf("unable to amend user %s ssh keys: %v", u.Name, err)
				}
			}
		}
	}

	for n, u := range r.users {
		if _, ok := userMap[n]; !ok {
			if err := r.removeUser(u); err != nil {
				log.Fatalf("unable to remove user %s: %v\n", u.Name, err)
			}
		}
	}

	return nil
}

func writeUserSSHKeys(user *IAMUser) error {
	lUser, err := osuser.Lookup(user.Name)
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

	for _, key := range user.SSHKeys {
		fp.Write(key)
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
