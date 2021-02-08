// +build linux,cgo

package generate

import (
	"context"
	"io/ioutil"
	"path/filepath"

	goSeccomp "github.com/containers/common/pkg/seccomp"
	"github.com/containers/podman/v2/libpod/image"
	"github.com/containers/podman/v2/pkg/seccomp"
	"github.com/containers/podman/v2/pkg/specgen"
	easyseccomp "github.com/giuseppe/easyseccomp/pkg/easyseccomp"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func getSeccompConfig(s *specgen.SpecGenerator, configSpec *spec.Spec, img *image.Image, tmpdir string) (*spec.LinuxSeccomp, map[string]string, error) {
	var seccompConfig *spec.LinuxSeccomp
	var err error
	scp, err := seccomp.LookupPolicy(s.SeccompPolicy)
	if err != nil {
		return nil, nil, err
	}

	if scp == seccomp.PolicyImage {
		if img == nil {
			return nil, nil, errors.New("cannot read seccomp profile without a valid image")
		}
		labels, err := img.Labels(context.Background())
		if err != nil {
			return nil, nil, err
		}
		imagePolicy := labels[seccomp.ContainerImageLabel]
		if len(imagePolicy) < 1 {
			return nil, nil, errors.New("no seccomp policy defined by image")
		}
		logrus.Debug("Loading seccomp profile from the security config")
		seccompConfig, err = goSeccomp.LoadProfile(imagePolicy, configSpec)
		if err != nil {
			return nil, nil, errors.Wrap(err, "loading seccomp profile failed")
		}
		return seccompConfig, nil, nil
	}

	if s.EasySeccompProfilePath != "" {
		logrus.Debugf("Loading easy seccomp profile from %q", s.EasySeccompProfilePath)
		opts := easyseccomp.LoadProfileOptions{
			TmpDir: filepath.Join(tmpdir, "easyseccomp"),
		}
		seccompConfig, annotations, err := easyseccomp.LoadProfile(s.EasySeccompProfilePath, configSpec, &opts)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "loading seccomp profile (%s) failed", s.EasySeccompProfilePath)
		}
		return seccompConfig, annotations, nil
	}

	if s.SeccompProfilePath != "" {
		logrus.Debugf("Loading seccomp profile from %q", s.SeccompProfilePath)
		seccompProfile, err := ioutil.ReadFile(s.SeccompProfilePath)
		if err != nil {
			return nil, nil, errors.Wrap(err, "opening seccomp profile failed")
		}
		seccompConfig, err = goSeccomp.LoadProfile(string(seccompProfile), configSpec)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "loading seccomp profile (%s) failed", s.SeccompProfilePath)
		}
	} else {
		logrus.Debug("Loading default seccomp profile")
		seccompConfig, err = goSeccomp.GetDefaultProfile(configSpec)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "loading seccomp profile (%s) failed", s.SeccompProfilePath)
		}
	}

	return seccompConfig, nil, nil
}
