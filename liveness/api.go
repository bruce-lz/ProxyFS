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
	Name        string
	VolumeGroup []*VolumeStruct
}

type PeerStruct struct {
	Name        string
	VolumeGroup []*VolumeGroupStruct
}

type ReportStruct struct {
	Peer []*PeerStruct
}

func FetchReport() (report *ReportStruct) {
	return fetchReport()
}
