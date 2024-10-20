package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	ifname = "eth0"
)

func main() {
	// Remove resource limits for kernel version 5.11 and earlier.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}

	// Load the eBPF program.
	var objs lbObjects
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatalf("can't load lb program: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("failed to get interface: %v", err)
	}

	// Attach the eBPF program to the interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("failed to attach XDP program: %v", err)
	}
	defer link.Close()

	log.Printf("Alright, we are counting packets on %s!\n", iface.Name)

	// Periodically read the map and print the packet count.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			log.Printf("helathy: %d\n", count)
		case <-stop:
			return
		}
	}
}
