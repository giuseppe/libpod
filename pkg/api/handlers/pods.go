package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"syscall"

	"github.com/containers/libpod/cmd/podman/shared"
	"github.com/containers/libpod/cmd/podman/shared/parse"
	"github.com/containers/libpod/libpod"
	"github.com/containers/libpod/libpod/define"
	"github.com/docker/docker/pkg/signal"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

func PodCreate(w http.ResponseWriter, r *http.Request) {
	var (
		runtime = r.Context().Value("runtime").(*libpod.Runtime)
		options []libpod.PodCreateOption
		err     error
	)
	labels := make(map[string]string)
	input := PodCreateConfig{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		Error(w, "Something went wrong.", http.StatusInternalServerError, errors.Wrap(err, "Decode()"))
		return
	}
	if len(input.InfraCommand) > 0 || len(input.InfraImage) > 0 {
		Error(w, "Something went wrong.", http.StatusInternalServerError,
			errors.New("infra-command and infra-image are not implemented yet"))
		return
	}
	// TODO long term we should break the following out of adapter and into libpod proper
	// so that the cli and api can share the creation of a pod with the same options
	if len(input.CGroupParent) > 0 {
		options = append(options, libpod.WithPodCgroupParent(input.CGroupParent))
	}

	if len(input.Labels) > 0 {
		if err := parse.ReadKVStrings(labels, []string{}, input.Labels); err != nil {
			Error(w, "Something went wrong.", http.StatusInternalServerError, err)
			return
		}
	}

	if len(labels) != 0 {
		options = append(options, libpod.WithPodLabels(labels))
	}

	if len(input.Name) > 0 {
		options = append(options, libpod.WithPodName(input.Name))
	}

	if len(input.Hostname) > 0 {
		options = append(options, libpod.WithPodHostname(input.Hostname))
	}

	if input.Infra {
		// TODO infra-image and infra-command are not supported in the libpod API yet.  Will fix
		// when implemented in libpod
		options = append(options, libpod.WithInfraContainer())
		sharedNamespaces := shared.DefaultKernelNamespaces
		if len(input.Share) > 0 {
			sharedNamespaces = input.Share
		}
		nsOptions, err := shared.GetNamespaceOptions(strings.Split(sharedNamespaces, ","))
		if err != nil {
			Error(w, "Something went wrong.", http.StatusInternalServerError, err)
			return
		}
		options = append(options, nsOptions...)
	}

	if len(input.Publish) > 0 {
		portBindings, err := shared.CreatePortBindings(input.Publish)
		if err != nil {
			Error(w, "Something went wrong.", http.StatusInternalServerError, err)
			return
		}
		options = append(options, libpod.WithInfraContainerPorts(portBindings))

	}
	// always have containers use pod cgroups
	// User Opt out is not yet supported
	options = append(options, libpod.WithPodCgroups())

	pod, err := runtime.NewPod(r.Context(), options...)
	if err != nil {
		Error(w, "Something went wrong.", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusCreated, IDResponse{ID: pod.CgroupParent()})
}

func Pods(w http.ResponseWriter, r *http.Request) {
	var (
		runtime        = r.Context().Value("runtime").(*libpod.Runtime)
		podInspectData []*libpod.PodInspect
	)

	filters := r.Form.Get("filter")
	if len(filters) > 0 {
		Error(w, "filters are not implemented yet", http.StatusInternalServerError, define.ErrNotImplemented)
		return
	}

	pods, err := runtime.GetAllPods()
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	for _, pod := range pods {
		data, err := pod.Inspect()
		if err != nil {
			Error(w, "Something went wrong", http.StatusInternalServerError, err)
			return
		}
		podInspectData = append(podInspectData, data)
	}
	WriteResponse(w, http.StatusOK, podInspectData)
}

func PodInspect(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	name := mux.Vars(r)["name"]
	pod, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}

	podData, err := pod.Inspect()
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusOK, podData)
}

func PodStop(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	var (
		stopError error
	)
	allContainersStopped := true
	name := mux.Vars(r)["name"]
	pod, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}

	// TODO we need to implement a pod.State/Status in libpod internal so libpod api
	// users dont have to run through all containers.
	podContainers, err := pod.AllContainers()
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}

	for _, con := range podContainers {
		containerState, err := con.State()
		if err != nil {
			Error(w, "Something went wrong", http.StatusInternalServerError, err)
			return
		}
		if containerState == define.ContainerStateRunning {
			allContainersStopped = false
			break
		}
	}
	if allContainersStopped {
		alreadyStopped := errors.Errorf("pod %s is already stopped", pod.ID())
		Error(w, "Something went wrong", http.StatusNotModified, alreadyStopped)
		return
	}

	if len(r.Form.Get("t")) > 0 {
		timeout, err := strconv.Atoi(r.Form.Get("t"))
		if err != nil {
			Error(w, "Something went wrong", http.StatusInternalServerError, err)
			return
		}
		_, stopError = pod.StopWithTimeout(r.Context(), false, timeout)
	} else {
		_, stopError = pod.Stop(r.Context(), false)
	}
	if stopError != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusOK, "")
}

func PodStart(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	allContainersRunning := true
	name := mux.Vars(r)["name"]
	pod, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}

	// TODO we need to implement a pod.State/Status in libpod internal so libpod api
	// users dont have to run through all containers.
	podContainers, err := pod.AllContainers()
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}

	for _, con := range podContainers {
		containerState, err := con.State()
		if err != nil {
			Error(w, "Something went wrong", http.StatusInternalServerError, err)
			return
		}
		if containerState != define.ContainerStateRunning {
			allContainersRunning = false
			break
		}
	}
	if allContainersRunning {
		alreadyRunning := errors.Errorf("pod %s is already running", pod.ID())
		Error(w, "Something went wrong", http.StatusNotModified, alreadyRunning)
		return
	}
	if _, err := pod.Start(r.Context()); err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusOK, "")
}

func PodDelete(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	name := mux.Vars(r)["name"]
	pod, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}
	force := false
	if len(r.Form.Get("force")) > 0 {
		force, err = strconv.ParseBool(r.Form.Get("force"))
		if err != nil {
			// If the parameter is bad, we pass back a 400
			Error(w, "Something went wrong", http.StatusBadRequest, err)
			return
		}
	}
	if err := runtime.RemovePod(r.Context(), pod, true, force); err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusOK, "")
}

func PodRestart(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	name := mux.Vars(r)["name"]
	pod, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}
	_, err = pod.Restart(r.Context())
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusOK, "")
}

func PodPrune(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	var (
		pods  []*libpod.Pod
		force bool
		err   error
	)
	if len(r.Form.Get("force")) > 0 {
		force, err = strconv.ParseBool(r.Form.Get("force"))
		if err != nil {
			Error(w, "Something went wrong", http.StatusInternalServerError, err)
			return
		}
	}
	if force {
		pods, err = runtime.GetAllPods()
	} else {
		// TODO We need to make a libpod.PruneVolumes or this code will be a mess.  Volumes
		// already does this right.  It will also help clean this code path up with less
		// conditionals. We do this when we integrate with libpod again.
		Error(w, "not implemented", http.StatusInternalServerError, errors.New("not implemented"))
		return
	}
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	for _, p := range pods {
		if err := runtime.RemovePod(r.Context(), p, true, force); err != nil {
			Error(w, "Something went wrong", http.StatusInternalServerError, err)
			return
		}
	}
	WriteResponse(w, http.StatusOK, "")
}

func PodPause(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	name := mux.Vars(r)["name"]
	pod, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}
	_, err = pod.Pause()
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusOK, "")
}

func PodUnpause(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	name := mux.Vars(r)["name"]
	pod, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}
	_, err = pod.Unpause()
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusOK, "")
}

func PodKill(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	name := mux.Vars(r)["name"]
	pod, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}
	podStates, err := pod.Status()
	if err != nil {
		Error(w, "Something went wrong.", http.StatusInternalServerError, err)
		return
	}
	hasRunning := false
	for _, s := range podStates {
		if s == define.ContainerStateRunning {
			hasRunning = true
			break
		}
	}
	if !hasRunning {
		msg := fmt.Sprintf("Container %s is not running", pod.ID())
		Error(w, msg, http.StatusConflict, errors.Errorf("cannot kill a pod with no running containers: %s", pod.ID()))
		return
	}
	sig := syscall.SIGKILL
	if len(r.Form.Get("signal")) > 0 {
		sig, err = signal.ParseSignal(r.Form.Get("signal"))
		if err != nil {
			Error(w, "Something went wrong.", http.StatusBadRequest, errors.Wrapf(err, "unable to parse signal %s", r.Form.Get("signal")))
			return
		}
	}
	_, err = pod.Kill(uint(sig))
	if err != nil {
		Error(w, "Something went wrong", http.StatusInternalServerError, err)
		return
	}
	WriteResponse(w, http.StatusOK, "")
}

func PodExists(w http.ResponseWriter, r *http.Request) {
	runtime := r.Context().Value("runtime").(*libpod.Runtime)

	name := mux.Vars(r)["name"]

	_, err := runtime.LookupPod(name)
	if err != nil {
		PodNotFound(w, name, err)
		return
	}
	WriteResponse(w, http.StatusOK, "")
}
