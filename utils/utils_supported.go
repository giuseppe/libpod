// +build linux darwin

package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/libpod/pkg/cgroups"
	"github.com/containers/libpod/pkg/rootless"
	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// RunUnderSystemdScope adds the specified pid to a systemd scope
func RunUnderSystemdScope(pid int, slice string, unitName string) error {
	var properties []systemdDbus.Property
	var conn *systemdDbus.Conn
	var err error

	if rootless.IsRootless() {
		conn, err = cgroups.GetUserConnection(rootless.GetRootlessUID())
		if err != nil {
			return err
		}
	} else {
		conn, err = systemdDbus.New()
		if err != nil {
			return err
		}
	}
	properties = append(properties, systemdDbus.PropSlice(slice))
	properties = append(properties, newProp("PIDs", []uint32{uint32(pid)}))
	properties = append(properties, newProp("Delegate", true))
	properties = append(properties, newProp("DefaultDependencies", false))
	ch := make(chan string)
	_, err = conn.StartTransientUnit(unitName, "replace", properties, ch)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Block until job is started
	<-ch

	return nil
}

// GetPidCgroup returns the cgroup for the specified pid.
func GetPidCgroup(pid int) (string, error) {
	if pid == 0 {
		pid = os.Getpid()
	}

	unified, err := cgroups.IsCgroup2UnifiedMode()
	if err != nil {
		return "", err
	}

	procFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(procFile)
	if err != nil {
		return "", errors.Wrapf(err, "open file %q", procFile)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	cgroup := ""
	for scanner.Scan() {
		line := scanner.Text()
		if unified && strings.HasPrefix(line, "0::") {
			cgroup = line[3:]
			break
		}
		if !unified && strings.HasPrefix(line[1:], ":pids:") {
			cgroup = line[7:]
			break
		}
	}
	if cgroup == "" {
		return "", errors.Errorf("could not find cgroup v2 mount in %q", procFile)
	}
	return cgroup, nil

}

func newProp(name string, units interface{}) systemdDbus.Property {
	return systemdDbus.Property{
		Name:  name,
		Value: dbus.MakeVariant(units),
	}
}
