//go:build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go bpf ./cgroup.bpf.c

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
// func detectCgroupPath() (string, error) {
// 	f, err := os.Open("/proc/mounts")
// 	if err != nil {
// 		return "", err
// 	}
// 	defer f.Close()

// 	scanner := bufio.NewScanner(f)
// 	for scanner.Scan() {
// 		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
// 		fields := strings.Split(scanner.Text(), " ")
// 		if len(fields) >= 3 && fields[2] == "cgroup2" {
// 			return fields[1], nil
// 		}
// 	}

// 	return "", errors.New("cgroup2 not mounted")
// }

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Get the first-mounted cgroupv2 path.
	// cgroupPath, err := detectCgroupPath()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	bindLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Bind,
		Program: objs.CgroupBind,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer bindLink.Close()

	connectLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CgroupConnect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer connectLink.Close()

	log.Println("cgroup programs attached...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

}
