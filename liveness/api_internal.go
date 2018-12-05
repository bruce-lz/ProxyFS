package liveness

func fetchReport() (report *ReportStruct) {
	globals.Lock()
	defer globals.Unlock()

	if !globals.active {
		// Not able to generate report, so return nil
		report = nil
		return
	}

	return &ReportStruct{Peer: make([]*PeerStruct, 0)} // TODO
}
