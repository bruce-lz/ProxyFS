package liveness

import "time"

const (
	StateAlive   = "alive"
	StateDead    = "dead"
	StateUnknown = "unknown"
)

type VolumeStruct struct {
	Name          string
	State         string // One of const State{Alive|Dead|Unknown}
	LastCheckTime time.Time
}

type VolumeGroupStruct struct {
	Name   string
	Volume []*VolumeStruct
}

type ServingPeerStruct struct {
	Name        string
	VolumeGroup []*VolumeGroupStruct
}

type ObservingPeerStruct struct {
	Name        string
	ServingPeer []*ServingPeerStruct
}

type ReportStruct struct {
	ObservingPeer []*ObservingPeerStruct
}

func FetchReport() (report *ReportStruct) {
	return fetchReport()
}
