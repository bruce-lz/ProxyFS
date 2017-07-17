package headhunter

import (
	"fmt"

	"github.com/swiftstack/conf"
)

const (
	firstNonceToProvide = uint64(2) // Must skip useful values: 0 == unassigned and 1 == RootDirInodeNumber
)

type variantHandle interface {
	up(confMap conf.ConfMap) (err error)
	down() (err error)
	fetchVolumeHandle(volumeName string) (volumeHandle VolumeHandle, err error)
}

type globalsStruct struct {
	variantHandle
	volumeList []string
}

var globals globalsStruct

// Up starts the headhunter package
func Up(confMap conf.ConfMap) (err error) {
	// Hard-code variant as using Swift

	globals.variantHandle = &swiftGlobals

	// Determine PrimaryPeer-selected volumeList

	whoAmI, err := confMap.FetchOptionValueString("Cluster", "WhoAmI")
	if nil != err {
		err = fmt.Errorf("confMap.FetchOptionValueStringSlice(\"Cluster\", \"WhoAmI\") failed: %v", err)
		return
	}

	volumeSectionNameSlice, err := confMap.FetchOptionValueStringSlice("FSGlobals", "VolumeList")
	if nil != err {
		err = fmt.Errorf("confMap.FetchOptionValueStringSlice(\"FSGlobals\", \"VolumeList\") failed: %v", err)
		return
	}

	globals.volumeList = make([]string, 0)

	for _, volumeName := range volumeSectionNameSlice {
		primaryPeer, nonShadowingErr := confMap.FetchOptionValueString(volumeName, "PrimaryPeer")
		if nil != nonShadowingErr {
			err = fmt.Errorf("confMap.FetchOptionValueStringSlice(\"%s\", \"PrimaryPeer\") failed: %v", volumeName, nonShadowingErr)
			return
		}

		if whoAmI == primaryPeer {
			globals.volumeList = append(globals.volumeList, volumeName)
		}
	}

	err = globals.variantHandle.up(confMap)

	return
}

// PauseAndContract pauses the headhunter package and applies any removals from the supplied confMap
func PauseAndContract(confMap conf.ConfMap) (err error) {
	err = nil // TODO
	return
}

// ExpandAndResume applies any additions from the supplied confMap and resumes the headhunter package
func ExpandAndResume(confMap conf.ConfMap) (err error) {
	err = nil // TODO
	return
}

// Down terminates the headhunter package
func Down() (err error) {
	err = globals.variantHandle.down()

	return
}
