// +build windows

package utils

import "github.com/pkg/errors"

func RunUnderSystemdScope(pid int, slice string, unitName string) error {
	return errors.New("not implemented for windows")
}

func MoveToCgroup2(cgroup string, subtree string) error {
	return errors.New("not implemented for windows")
}

func GetPidCgroup(pid int) (string, error) {
	return "", errors.New("not implemented for windows")
}
