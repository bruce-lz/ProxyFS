package liveness

func fetchReport() (report *ReportStruct) {
	var (
		observingPeer               *ObservingPeerStruct
		internalObservingPeerReport *internalObservingPeerReportStruct
		servingPeer                 *ServingPeerStruct
		internalServingPeerReport   *internalServingPeerReportStruct
		volumeGroup                 *VolumeGroupStruct
		internalVolumeGroupReport   *internalVolumeGroupReportStruct
		volume                      *VolumeStruct
		internalVolumeReport        *internalVolumeReportStruct
	)

	globals.Lock()
	defer globals.Unlock()

	if !globals.active || (nil == globals.livenessReport) {
		// Not able to generate report, so return nil
		report = nil
		return
	}

	report = &ReportStruct{
		ObservingPeer: make([]*ObservingPeerStruct, 0, len(globals.livenessReport.observingPeer)),
	}

	for _, internalObservingPeerReport = range globals.livenessReport.observingPeer {
		observingPeer = &ObservingPeerStruct{
			Name:        internalObservingPeerReport.name,
			ServingPeer: make([]*ServingPeerStruct, 0, len(internalObservingPeerReport.servingPeer)),
		}

		for _, internalServingPeerReport = range internalObservingPeerReport.servingPeer {
			servingPeer = &ServingPeerStruct{
				Name:        internalServingPeerReport.name,
				VolumeGroup: make([]*VolumeGroupStruct, 0, len(internalServingPeerReport.volumeGroup)),
			}

			for _, internalVolumeGroupReport = range internalServingPeerReport.volumeGroup {
				volumeGroup = &VolumeGroupStruct{
					Name:   internalVolumeGroupReport.name,
					Volume: make([]*VolumeStruct, 0, len(internalVolumeGroupReport.volume)),
				}

				for _, internalVolumeReport = range internalVolumeGroupReport.volume {
					volume = &VolumeStruct{
						Name:          internalVolumeReport.name,
						State:         internalVolumeReport.state,
						LastCheckTime: internalVolumeReport.lastCheckTime,
					}

					volumeGroup.Volume = append(volumeGroup.Volume, volume)
				}

				servingPeer.VolumeGroup = append(servingPeer.VolumeGroup, volumeGroup)
			}

			observingPeer.ServingPeer = append(observingPeer.ServingPeer, servingPeer)
		}

		report.ObservingPeer = append(report.ObservingPeer, observingPeer)
	}

	return
}
