package main

import (
	"log"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	"github.com/swiftstack/ProxyFS/conf"
	"github.com/swiftstack/ProxyFS/transitions"

	// Force importing of liveness package
	_ "github.com/swiftstack/ProxyFS/liveness"
)

func main() {
	var (
		args       []string
		confMap    conf.ConfMap
		err        error
		signalChan chan os.Signal
	)

	// Parse arguments
	args = os.Args[1:]
	if 0 == len(args) {
		log.Fatalf("No .conf file specified")
	}
	confMap, err = conf.MakeConfMapFromFile(args[0])
	if nil != err {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Update confMap with any extra os.Args supplied
	err = confMap.UpdateFromStrings(args[1:])
	if nil != err {
		log.Fatalf("Failed to load config overrides: %v", err)
	}

	// Upgrade confMap if necessary
	err = transitions.UpgradeConfMapIfNeeded(confMap)
	if nil != err {
		log.Fatalf("Failed to upgrade config: %v", err)
	}

	// Start everything up
	err = transitions.Up(confMap)
	if nil != err {
		log.Fatalf("transitions.Up() failed: %v", err)
	}

	// Wait for SIGINT or SIGTERM (not handling SIGHUP) before shutting down
	signalChan = make(chan os.Signal)
	signal.Notify(signalChan, unix.SIGINT, unix.SIGTERM)
	_ = <-signalChan

	// Cleanly shutdown
	err = transitions.Down(confMap)
	if nil != err {
		log.Fatalf("transitions.Up() failed: %v", err)
	}
}
