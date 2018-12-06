package liveness

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"hash/crc64"
	"net"
	"reflect"
	"time"

	"github.com/swiftstack/ProxyFS/logger"
)

func stateMachine() {
	for {
		globals.nextState()
		if globals.stateMachineStopped {
			globals.stateMachineDone.Done()
			return
		}
	}
}

func fetchNonceWhileLocked() (nonce uint64) {
	nonce = globals.nextNonce
	globals.nextNonce++
	if 0 == globals.nextNonce {
		globals.nextNonce = 1
	}
	return
}

func fetchNonce() (nonce uint64) {
	globals.Lock()
	nonce = fetchNonceWhileLocked()
	globals.Unlock()
	return
}

func serializeU64LittleEndian(u64 uint64) (u64Buf []byte) {
	u64Buf = make([]byte, 8)
	u64Buf[0] = byte(u64 & 0xFF)
	u64Buf[1] = byte((u64 >> 8) & 0xFF)
	u64Buf[2] = byte((u64 >> 16) & 0xFF)
	u64Buf[3] = byte((u64 >> 24) & 0xFF)
	u64Buf[4] = byte((u64 >> 32) & 0xFF)
	u64Buf[5] = byte((u64 >> 40) & 0xFF)
	u64Buf[6] = byte((u64 >> 48) & 0xFF)
	u64Buf[7] = byte((u64 >> 56) & 0xFF)
	return
}

func deserializeU64LittleEndian(u64Buf []byte) (u64 uint64) {
	u64 = uint64(u64Buf[7])
	u64 = (u64 << 8) | uint64(u64Buf[6])
	u64 = (u64 << 8) | uint64(u64Buf[5])
	u64 = (u64 << 8) | uint64(u64Buf[4])
	u64 = (u64 << 8) | uint64(u64Buf[3])
	u64 = (u64 << 8) | uint64(u64Buf[2])
	u64 = (u64 << 8) | uint64(u64Buf[1])
	u64 = (u64 << 8) | uint64(u64Buf[0])
	return
}

func appendGlobalRecvMsgQueueElementWhileLocked(recvMsgQueueElement *recvMsgQueueElementStruct) {
	recvMsgQueueElement.globalRecvMsgQueueElement = globals.recvMsgQueue.PushBack(recvMsgQueueElement)
}
func appendGlobalRecvMsgQueueElement(recvMsgQueueElement *recvMsgQueueElementStruct) {
	globals.Lock()
	appendGlobalRecvMsgQueueElementWhileLocked(recvMsgQueueElement)
	globals.Unlock()
}

func removeGlobalRecvMsgQueueElementWhileLocked(recvMsgQueueElement *recvMsgQueueElementStruct) {
	_ = globals.recvMsgQueue.Remove(recvMsgQueueElement.globalRecvMsgQueueElement)
}
func removeGlobalRecvMsgQueueElement(recvMsgQueueElement *recvMsgQueueElementStruct) {
	globals.Lock()
	removeGlobalRecvMsgQueueElementWhileLocked(recvMsgQueueElement)
	globals.Unlock()
}

func popGlobalMsgWhileLocked() (recvMsgQueueElement *recvMsgQueueElementStruct) {
	if 0 == globals.recvMsgQueue.Len() {
		recvMsgQueueElement = nil
	} else {
		recvMsgQueueElement = globals.recvMsgQueue.Front().Value.(*recvMsgQueueElementStruct)
		recvMsgQueueElement.peer.completeRecvMsgQueue.Remove(recvMsgQueueElement.peerRecvMsgQueueElement)
		removeGlobalRecvMsgQueueElementWhileLocked(recvMsgQueueElement)
	}
	return
}
func popGlobalMsg() (recvMsgQueueElement *recvMsgQueueElementStruct) {
	globals.Lock()
	recvMsgQueueElement = popGlobalMsgWhileLocked()
	globals.Unlock()
	return
}

func recvMsgs() {
	var (
		computedCRC64       uint64
		err                 error
		msgBuf              []byte
		msgNonce            uint64
		msgTypeStruct       MsgTypeStruct
		ok                  bool
		packetBuf           []byte
		packetCount         uint8
		packetIndex         uint8
		packetSize          int
		peer                *peerStruct
		receivedCRC64       uint64
		recvMsgQueueElement *recvMsgQueueElementStruct
		udpAddr             *net.UDPAddr
	)

	for {
		// Read next packet

		packetBuf = make([]byte, globals.udpPacketRecvSize)

		packetSize, udpAddr, err = globals.myUDPConn.ReadFromUDP(packetBuf)

		if nil != err {
			globals.recvMsgsDoneChan <- struct{}{}
			return
		}

		// Decode packet header

		if uint64(packetSize) < udpPacketHeaderSize {
			continue // Ignore it
		}

		packetBuf = packetBuf[:packetSize]

		receivedCRC64 = deserializeU64LittleEndian(packetBuf[:8])
		msgNonce = deserializeU64LittleEndian(packetBuf[8:16])
		packetIndex = packetBuf[16]
		packetCount = packetBuf[17]

		// Validate packet

		computedCRC64 = crc64.Checksum(packetBuf[8:], globals.crc64ECMATable)

		if receivedCRC64 != computedCRC64 {
			continue // Ignore it
		}

		if 0 == msgNonce {
			continue // Ignore it
		}

		if packetIndex >= packetCount {
			continue // Ignore it
		}

		if packetCount > globals.udpPacketCapPerMessage {
			continue // Ignore it
		}

		// Locate peer

		globals.Lock()
		peer, ok = globals.peersByTuple[udpAddr.String()]
		globals.Unlock()

		if !ok {
			continue // Ignore it
		}

		// Check if packet is part of a new msg

		recvMsgQueueElement, ok = peer.incompleteRecvMsgMap[msgNonce]
		if ok {
			// Packet is part of an existing incomplete msg

			peer.incompleteRecvMsgQueue.MoveToBack(recvMsgQueueElement.peerRecvMsgQueueElement)

			if packetCount != recvMsgQueueElement.packetCount {
				// Forget prior msg packets and start receiving a new msg with this packet

				recvMsgQueueElement.packetCount = packetCount
				recvMsgQueueElement.packetSumSize = uint64(len(packetBuf[18:]))
				recvMsgQueueElement.packetMap = make(map[uint8][]byte)

				recvMsgQueueElement.packetMap[packetIndex] = packetBuf[18:]
			} else {
				// Update existing incomplete msg with this packet

				_, ok = recvMsgQueueElement.packetMap[packetIndex]
				if ok {
					continue // Ignore it
				}

				recvMsgQueueElement.packetSumSize += uint64(len(packetBuf[18:]))
				recvMsgQueueElement.packetMap[packetIndex] = packetBuf[18:]
			}
		} else {
			// Packet is part of a new msg

			if uint64(peer.incompleteRecvMsgQueue.Len()) >= globals.messageQueueDepthPerPeer {
				// Make room for this new msg in .incompleteRecvMsgQueue

				recvMsgQueueElement = peer.incompleteRecvMsgQueue.Front().Value.(*recvMsgQueueElementStruct)
				delete(peer.incompleteRecvMsgMap, recvMsgQueueElement.msgNonce)
				_ = peer.incompleteRecvMsgQueue.Remove(recvMsgQueueElement.peerRecvMsgQueueElement)
			}

			// Contstruct a new recvMsgQueueElement

			recvMsgQueueElement = &recvMsgQueueElementStruct{
				peer:          peer,
				msgNonce:      msgNonce,
				packetCount:   packetCount,
				packetSumSize: uint64(len(packetBuf[18:])),
				packetMap:     make(map[uint8][]byte),
			}

			recvMsgQueueElement.packetMap[packetIndex] = packetBuf[18:]

			peer.incompleteRecvMsgMap[recvMsgQueueElement.msgNonce] = recvMsgQueueElement
			recvMsgQueueElement.peerRecvMsgQueueElement = peer.incompleteRecvMsgQueue.PushBack(recvMsgQueueElement)
		}

		// Have all packets of msg been received?

		if len(recvMsgQueueElement.packetMap) == int(recvMsgQueueElement.packetCount) {
			// All packets received... assemble completed msg

			delete(peer.incompleteRecvMsgMap, recvMsgQueueElement.msgNonce)
			_ = peer.incompleteRecvMsgQueue.Remove(recvMsgQueueElement.peerRecvMsgQueueElement)

			msgBuf = make([]byte, 0, recvMsgQueueElement.packetSumSize)

			for packetIndex = 0; packetIndex < recvMsgQueueElement.packetCount; packetIndex++ {
				msgBuf = append(msgBuf, recvMsgQueueElement.packetMap[packetIndex]...)
			}

			// Decode the msg

			msgTypeStruct = MsgTypeStruct{}

			err = json.Unmarshal(msgBuf, &msgTypeStruct)
			if nil != err {
				continue // Ignore it
			}

			recvMsgQueueElement.msgType = msgTypeStruct.MsgType

			switch recvMsgQueueElement.msgType {
			case MsgTypeHeartBeatRequest:
				recvMsgQueueElement.msg = &HeartBeatRequestStruct{}
			case MsgTypeHeartBeatResponse:
				recvMsgQueueElement.msg = &HeartBeatResponseStruct{}
			case MsgTypeRequestVoteRequest:
				recvMsgQueueElement.msg = &RequestVoteRequestStruct{}
			case MsgTypeRequestVoteResponse:
				recvMsgQueueElement.msg = &RequestVoteResponseStruct{}
			default:
				continue // Ignore it
			}

			err = json.Unmarshal(msgBuf, recvMsgQueueElement.msg)
			if nil != err {
				continue // Ignore it
			}

			// Deliver msg

			globals.Lock()

			recvMsgQueueElement.peerRecvMsgQueueElement = peer.completeRecvMsgQueue.PushBack(recvMsgQueueElement)

			appendGlobalRecvMsgQueueElementWhileLocked(recvMsgQueueElement)

			globals.Unlock()

			globals.recvMsgChan <- struct{}{}

			// Log delivery if requested

			if LogLevelMessages <= globals.logLevel {
				if LogLevelMessageDetails > globals.logLevel {
					logger.Infof("%s rec'd %s from %s", globals.myUDPAddr, reflect.TypeOf(recvMsgQueueElement.msg), udpAddr)
				} else {
					logger.Infof("%s rec'd %s from %s [%#v]", globals.myUDPAddr, reflect.TypeOf(recvMsgQueueElement.msg), udpAddr, recvMsgQueueElement.msg)
				}
			}
		}
	}
}

// sendMsg JSON-encodes msg and sends it to peer (all peers if nil == peer)
func sendMsg(peer *peerStruct, msg interface{}) (peers []*peerStruct, err error) {
	var (
		computedCRC64    uint64
		computedCRC64Buf []byte
		loggerInfofBuf   string
		msgBuf           []byte
		msgBufOffset     uint64
		msgBufSize       uint64
		msgNonce         uint64
		msgNonceBuf      []byte
		packetBuf        []byte
		packetBufIndex   uint64
		packetCount      uint8
		packetIndex      uint8
	)

	if nil == peer {
		globals.Lock()
		peers = make([]*peerStruct, 0, len(globals.peersByTuple))
		for _, peer = range globals.peersByTuple {
			peers = append(peers, peer)
		}
		globals.Unlock()
	} else {
		peers = make([]*peerStruct, 1)
		peers[0] = peer
	}

	msgNonce = fetchNonce()

	msgBuf, err = json.Marshal(msg)
	if nil != err {
		return
	}

	msgBufSize = uint64(len(msgBuf))

	if msgBufSize > globals.sendMsgMessageSizeMax {
		err = fmt.Errorf("sendMsg() called for excessive len(msgBuf) == %v (must be <= %v)", msgBufSize, globals.sendMsgMessageSizeMax)
		return
	}

	packetCount = uint8((msgBufSize + globals.udpPacketSendPayloadSize - 1) / globals.udpPacketSendPayloadSize)

	msgNonceBuf = serializeU64LittleEndian(msgNonce)

	msgBufOffset = 0

	for packetIndex = 0; packetIndex < packetCount; packetIndex++ {
		if packetIndex < (packetCount - 1) {
			packetBuf = make([]byte, udpPacketHeaderSize, globals.udpPacketSendSize)
			packetBuf = append(packetBuf, msgBuf[msgBufOffset:msgBufOffset+globals.udpPacketSendPayloadSize]...)
			msgBufOffset += globals.udpPacketSendPayloadSize
		} else { // packetIndex == (packetCount - 1)
			packetBuf = make([]byte, udpPacketHeaderSize, udpPacketHeaderSize+msgBufSize-msgBufOffset)
			packetBuf = append(packetBuf, msgBuf[msgBufOffset:]...)
		}

		for packetBufIndex = uint64(8); packetBufIndex < uint64(16); packetBufIndex++ {
			packetBuf[packetBufIndex] = msgNonceBuf[packetBufIndex-8]
		}

		packetBuf[16] = packetIndex
		packetBuf[17] = packetCount

		computedCRC64 = crc64.Checksum(packetBuf[8:], globals.crc64ECMATable)
		computedCRC64Buf = serializeU64LittleEndian(computedCRC64)

		for packetBufIndex = uint64(0); packetBufIndex < uint64(8); packetBufIndex++ {
			packetBuf[packetBufIndex] = computedCRC64Buf[packetBufIndex]
		}

		for _, peer = range peers {
			_, err = globals.myUDPConn.WriteToUDP(packetBuf, peer.udpAddr)
			if nil != err {
				err = fmt.Errorf("sendMsg() failed writing to %v: %v", peer.udpAddr, err)
				return
			}
		}
	}

	if LogLevelMessages <= globals.logLevel {
		loggerInfofBuf = fmt.Sprintf("%s sent %s to", globals.myUDPAddr, reflect.TypeOf(msg))
		for _, peer = range peers {
			loggerInfofBuf = loggerInfofBuf + fmt.Sprintf(" %s", peer.udpAddr)
		}
		if LogLevelMessageDetails <= globals.logLevel {
			loggerInfofBuf = loggerInfofBuf + fmt.Sprintf(" [%#v]", msg)
		}
		logger.Info(loggerInfofBuf)
	}

	err = nil
	return
}

func doCandidate() {
	var (
		awaitingResponses                               map[*peerStruct]struct{}
		durationDelta                                   time.Duration
		err                                             error
		msgAsHeartBeatRequest                           *HeartBeatRequestStruct
		msgAsHeartBeatResponse                          *HeartBeatResponseStruct
		msgAsRequestVoteRequest                         *RequestVoteRequestStruct
		msgAsRequestVoteResponse                        *RequestVoteResponseStruct
		ok                                              bool
		recvMsgQueueElement                             *recvMsgQueueElementStruct
		peer                                            *peerStruct
		peers                                           []*peerStruct
		randByteBuf                                     []byte
		requestVoteSuccessfulResponses                  uint64
		requestVoteSuccessfulResponsesRequiredForQuorum uint64
		requestVoteExpirationTime                       time.Time
		requestVoteExpirationDurationRemaining          time.Duration
		timeNow                                         time.Time
	)

	if LogLevelStateChanges <= globals.logLevel {
		logger.Infof("%s entered Candidate state", globals.myUDPAddr)
	}

	globals.currentTerm++

	msgAsRequestVoteRequest = &RequestVoteRequestStruct{MsgType: MsgTypeRequestVoteRequest, CandidateTerm: globals.currentTerm}

	peers, err = sendMsg(nil, msgAsRequestVoteRequest)
	if nil != err {
		panic(err)
	}

	// Minimize split votes by picking a requestVoteExpirationTime at some random
	// point between globals.heartbeatDuration and globals.heartbeatMissDuration

	randByteBuf = make([]byte, 1)
	_, err = rand.Read(randByteBuf)
	if nil != err {
		err = fmt.Errorf("rand.Read(randByteBuf) failed: %v", err)
		panic(err)
	}

	durationDelta = globals.heartbeatMissDuration - globals.heartbeatDuration
	durationDelta *= time.Duration(randByteBuf[0])
	durationDelta /= time.Duration(0x100)
	durationDelta += globals.heartbeatDuration

	requestVoteExpirationTime = time.Now().Add(durationDelta)

	awaitingResponses = make(map[*peerStruct]struct{})
	for _, peer = range peers {
		awaitingResponses[peer] = struct{}{}
	}

	requestVoteSuccessfulResponsesRequiredForQuorum = (uint64(len(awaitingResponses)) + 1) / 2
	requestVoteSuccessfulResponses = 0

	for {
		timeNow = time.Now()

		if timeNow.After(requestVoteExpirationTime) || timeNow.Equal(requestVoteExpirationTime) {
			// Simply return to try again
			return
		}

		requestVoteExpirationDurationRemaining = requestVoteExpirationTime.Sub(timeNow)

		select {
		case <-globals.stopStateMachineChan:
			globals.stateMachineStopped = true
			return
		case <-globals.recvMsgChan:
			recvMsgQueueElement = popGlobalMsg()
			if nil != recvMsgQueueElement {
				peer = recvMsgQueueElement.peer
				switch recvMsgQueueElement.msgType {
				case MsgTypeHeartBeatRequest:
					msgAsHeartBeatRequest = recvMsgQueueElement.msg.(*HeartBeatRequestStruct)
					if msgAsHeartBeatRequest.LeaderTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsHeartBeatRequest.LeaderTerm == globals.currentTerm {
						// Somebody else must have won the election... so convert to Follower
						globals.currentLeader = peer
						msgAsHeartBeatResponse = &HeartBeatResponseStruct{MsgType: MsgTypeHeartBeatResponse, CurrentTerm: globals.currentTerm, Nonce: msgAsHeartBeatRequest.Nonce, Success: true}
						_, err = sendMsg(peer, msgAsHeartBeatResponse)
						if nil != err {
							panic(err)
						}
						globals.nextState = doFollower
						return
					} else { // msgAsHeartBeatRequest.LeaderTerm > globals.currentTerm
						globals.currentTerm = msgAsHeartBeatRequest.LeaderTerm
						// We missed a subsequent election, so convert to Follower state
						globals.currentLeader = peer
						msgAsHeartBeatResponse = &HeartBeatResponseStruct{MsgType: MsgTypeHeartBeatResponse, CurrentTerm: globals.currentTerm, Nonce: msgAsHeartBeatRequest.Nonce, Success: true}
						_, err = sendMsg(peer, msgAsHeartBeatResponse)
						if nil != err {
							panic(err)
						}
						globals.nextState = doFollower
						return
					}
				case MsgTypeHeartBeatResponse:
					msgAsHeartBeatResponse = recvMsgQueueElement.msg.(*HeartBeatResponseStruct)
					if msgAsHeartBeatResponse.CurrentTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsHeartBeatResponse.CurrentTerm == globals.currentTerm {
						// Unexpected... so convert to Follower state
						globals.nextState = doFollower
						return
					} else { // msgAsHeartBeatResponse.CurrentTerm > globals.currentTerm
						globals.currentTerm = msgAsHeartBeatResponse.CurrentTerm
						// Convert to Follower state
						globals.nextState = doFollower
						return
					}
				case MsgTypeRequestVoteRequest:
					msgAsRequestVoteRequest = recvMsgQueueElement.msg.(*RequestVoteRequestStruct)
					if msgAsRequestVoteRequest.CandidateTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsRequestVoteRequest.CandidateTerm == globals.currentTerm {
						// We voted for ourself, so vote no
						msgAsRequestVoteResponse = &RequestVoteResponseStruct{MsgType: MsgTypeRequestVoteResponse, CurrentTerm: globals.currentTerm, VoteGranted: false}
						_, err = sendMsg(peer, msgAsRequestVoteResponse)
						if nil != err {
							panic(err)
						}
					} else { // msgAsRequestVoteRequest.CandidateTerm > globals.currentTerm
						globals.currentTerm = msgAsRequestVoteRequest.CandidateTerm
						// Abandon our election, vote yes, and convert to Follower
						globals.currentLeader = nil
						globals.currentVote = peer
						msgAsRequestVoteResponse = &RequestVoteResponseStruct{MsgType: MsgTypeRequestVoteResponse, CurrentTerm: globals.currentTerm, VoteGranted: true}
						_, err = sendMsg(peer, msgAsRequestVoteResponse)
						if nil != err {
							panic(err)
						}
						globals.nextState = doFollower
						return
					}
				case MsgTypeRequestVoteResponse:
					msgAsRequestVoteResponse = recvMsgQueueElement.msg.(*RequestVoteResponseStruct)
					if msgAsRequestVoteResponse.CurrentTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsRequestVoteResponse.CurrentTerm == globals.currentTerm {
						// If this is an unduplicated VoteGranted==true response, check if we are now Leader
						_, ok = awaitingResponses[peer]
						if ok {
							delete(awaitingResponses, peer)
							if msgAsRequestVoteResponse.VoteGranted {
								requestVoteSuccessfulResponses++
								if requestVoteSuccessfulResponses >= requestVoteSuccessfulResponsesRequiredForQuorum {
									// Convert to Leader
									globals.nextState = doLeader
									return
								}
							}
						}
					} else { // msgAsRequestVoteResponse.CurrentTerm > globals.currentTerm
						globals.currentTerm = msgAsRequestVoteResponse.CurrentTerm
						// Unexpected... so convert to Follower state
						globals.nextState = doFollower
						return
					}
				default:
					err = fmt.Errorf("Unexpected recvMsgQueueElement.msg: %v", reflect.TypeOf(recvMsgQueueElement.msg))
					panic(err)
				}
			}
		case <-time.After(requestVoteExpirationDurationRemaining):
			// We didn't win... but nobody else claims to have either.. so simply return to try again
			return
		}
	}
}

func doFollower() {
	var (
		err                            error
		heartbeatMissTime              time.Time
		heartbeatMissDurationRemaining time.Duration
		msgAsHeartBeatRequest          *HeartBeatRequestStruct
		msgAsHeartBeatResponse         *HeartBeatResponseStruct
		msgAsRequestVoteRequest        *RequestVoteRequestStruct
		msgAsRequestVoteResponse       *RequestVoteResponseStruct
		peer                           *peerStruct
		recvMsgQueueElement            *recvMsgQueueElementStruct
		timeNow                        time.Time
	)

	if LogLevelStateChanges <= globals.logLevel {
		logger.Infof("%s entered Follower state", globals.myUDPAddr)
	}

	heartbeatMissTime = time.Now().Add(globals.heartbeatMissDuration)

	for {
		timeNow = time.Now()

		if timeNow.After(heartbeatMissTime) || timeNow.Equal(heartbeatMissTime) {
			globals.nextState = doCandidate
			return
		}

		heartbeatMissDurationRemaining = heartbeatMissTime.Sub(timeNow)

		select {
		case <-globals.stopStateMachineChan:
			globals.stateMachineStopped = true
			return
		case <-globals.recvMsgChan:
			recvMsgQueueElement = popGlobalMsg()
			if nil != recvMsgQueueElement {
				peer = recvMsgQueueElement.peer
				switch recvMsgQueueElement.msgType {
				case MsgTypeHeartBeatRequest:
					msgAsHeartBeatRequest = recvMsgQueueElement.msg.(*HeartBeatRequestStruct)
					if msgAsHeartBeatRequest.LeaderTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsHeartBeatRequest.LeaderTerm == globals.currentTerm {
						// In case this is the first, record .currentLeader
						globals.currentLeader = peer
						globals.currentVote = nil
						// Send HeartBeat response
						msgAsHeartBeatResponse = &HeartBeatResponseStruct{MsgType: MsgTypeHeartBeatResponse, CurrentTerm: globals.currentTerm, Nonce: msgAsHeartBeatRequest.Nonce, Success: true}
						_, err = sendMsg(peer, msgAsHeartBeatResponse)
						if nil != err {
							panic(err)
						}
						// Reset heartBeatMissTime
						heartbeatMissTime = time.Now().Add(globals.heartbeatMissDuration)
					} else { // msgAsHeartBeatRequest.LeaderTerm > globals.currentTerm
						globals.currentTerm = msgAsHeartBeatRequest.LeaderTerm
						// We missed out on Leader election, so record .currentLeader
						globals.currentLeader = peer
						globals.currentVote = nil
						// Send HeartBeat response
						msgAsHeartBeatResponse = &HeartBeatResponseStruct{MsgType: MsgTypeHeartBeatResponse, CurrentTerm: globals.currentTerm, Nonce: msgAsHeartBeatRequest.Nonce, Success: true}
						_, err = sendMsg(peer, msgAsHeartBeatResponse)
						if nil != err {
							panic(err)
						}
						// Reset heartBeatMissTime
						heartbeatMissTime = time.Now().Add(globals.heartbeatMissDuration)
					}
				case MsgTypeHeartBeatResponse:
					msgAsHeartBeatResponse = recvMsgQueueElement.msg.(*HeartBeatResponseStruct)
					if msgAsHeartBeatResponse.CurrentTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsHeartBeatResponse.CurrentTerm == globals.currentTerm {
						// Unexpected... but ignore it
					} else { // msgAsHeartBeatResponse.CurrentTerm > globals.currentTerm
						globals.currentTerm = msgAsHeartBeatResponse.CurrentTerm
						// Unexpected... but ignore it
					}
				case MsgTypeRequestVoteRequest:
					msgAsRequestVoteRequest = recvMsgQueueElement.msg.(*RequestVoteRequestStruct)
					if msgAsRequestVoteRequest.CandidateTerm < globals.currentTerm {
						// Reject it
						msgAsRequestVoteResponse = &RequestVoteResponseStruct{MsgType: MsgTypeRequestVoteResponse, CurrentTerm: globals.currentTerm, VoteGranted: false}
						_, err = sendMsg(peer, msgAsRequestVoteResponse)
						if nil != err {
							panic(err)
						}
					} else if msgAsRequestVoteRequest.CandidateTerm == globals.currentTerm {
						if nil != globals.currentLeader {
							// Candidate missed Leader election, so vote no
							msgAsRequestVoteResponse = &RequestVoteResponseStruct{MsgType: MsgTypeRequestVoteResponse, CurrentTerm: globals.currentTerm, VoteGranted: false}
							_, err = sendMsg(peer, msgAsRequestVoteResponse)
							if nil != err {
								panic(err)
							}
						} else {
							if peer == globals.currentVote {
								// Candidate we voted for missed our yes vote and we received msg twice, so vote yes again
								msgAsRequestVoteResponse = &RequestVoteResponseStruct{MsgType: MsgTypeRequestVoteResponse, CurrentTerm: globals.currentTerm, VoteGranted: true}
								_, err = sendMsg(peer, msgAsRequestVoteResponse)
								if nil != err {
									panic(err)
								}
								// Reset heartBeatMissTime
								heartbeatMissTime = time.Now().Add(globals.heartbeatMissDuration)
							} else { // peer != globals.currentVote
								// We voted for someone else or didn't vote, so vote no
								msgAsRequestVoteResponse = &RequestVoteResponseStruct{MsgType: MsgTypeRequestVoteResponse, CurrentTerm: globals.currentTerm, VoteGranted: false}
								_, err = sendMsg(peer, msgAsRequestVoteResponse)
								if nil != err {
									panic(err)
								}
							}
						}
					} else { // msgAsRequestVoteRequest.CandidateTerm > globals.currentTerm
						globals.currentTerm = msgAsRequestVoteRequest.CandidateTerm
						// Vote yes
						globals.currentLeader = nil
						globals.currentVote = peer
						msgAsRequestVoteResponse = &RequestVoteResponseStruct{MsgType: MsgTypeRequestVoteResponse, CurrentTerm: globals.currentTerm, VoteGranted: true}
						_, err = sendMsg(peer, msgAsRequestVoteResponse)
						if nil != err {
							panic(err)
						}
						// Reset heartBeatMissTime
						heartbeatMissTime = time.Now().Add(globals.heartbeatMissDuration)
					}
				case MsgTypeRequestVoteResponse:
					msgAsRequestVoteResponse = recvMsgQueueElement.msg.(*RequestVoteResponseStruct)
					if msgAsRequestVoteResponse.CurrentTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsRequestVoteResponse.CurrentTerm == globals.currentTerm {
						// Ignore it
					} else { // msgAsRequestVoteResponse.CurrentTerm > globals.currentTerm
						globals.currentTerm = msgAsRequestVoteResponse.CurrentTerm
					}
				default:
					err = fmt.Errorf("Unexpected recvMsgQueueElement.msg: %v", reflect.TypeOf(recvMsgQueueElement.msg))
					panic(err)
				}
			}
		case <-time.After(heartbeatMissDurationRemaining):
			globals.nextState = doCandidate
			return
		}
	}
}

func doLeader() {
	var (
		awaitingResponses                             map[*peerStruct]struct{}
		err                                           error
		heartbeatDurationRemaining                    time.Duration
		heartbeatNonce                                uint64
		heartbeatSendTime                             time.Time
		heartbeatSuccessfulResponses                  uint64
		heartbeatSuccessfulResponsesRequiredForQuorum uint64
		msgAsHeartBeatRequest                         *HeartBeatRequestStruct
		msgAsHeartBeatResponse                        *HeartBeatResponseStruct
		msgAsRequestVoteRequest                       *RequestVoteRequestStruct
		msgAsRequestVoteResponse                      *RequestVoteResponseStruct
		ok                                            bool
		peer                                          *peerStruct
		peers                                         []*peerStruct
		recvMsgQueueElement                           *recvMsgQueueElementStruct
		timeNow                                       time.Time
	)

	if LogLevelStateChanges <= globals.logLevel {
		logger.Infof("%s entered Leader state", globals.myUDPAddr)
	}

	heartbeatSendTime = time.Now() // Force first time through for{} loop to send a heartbeat

	for {
		timeNow = time.Now()

		if timeNow.Before(heartbeatSendTime) {
			heartbeatDurationRemaining = heartbeatSendTime.Sub(timeNow)
		} else {
			heartbeatNonce = fetchNonce()

			msgAsHeartBeatRequest = &HeartBeatRequestStruct{MsgType: MsgTypeHeartBeatRequest, LeaderTerm: globals.currentTerm, Nonce: heartbeatNonce}

			peers, err = sendMsg(nil, msgAsHeartBeatRequest)
			if nil != err {
				panic(err)
			}

			heartbeatSendTime = timeNow.Add(globals.heartbeatDuration)
			heartbeatDurationRemaining = globals.heartbeatDuration

			awaitingResponses = make(map[*peerStruct]struct{})
			for _, peer = range peers {
				awaitingResponses[peer] = struct{}{}
			}

			heartbeatSuccessfulResponsesRequiredForQuorum = (uint64(len(awaitingResponses)) + 1) / 2
			heartbeatSuccessfulResponses = 0
		}

		select {
		case <-globals.stopStateMachineChan:
			globals.stateMachineStopped = true
			return
		case <-globals.recvMsgChan:
			recvMsgQueueElement = popGlobalMsg()
			if nil != recvMsgQueueElement {
				peer = recvMsgQueueElement.peer
				switch recvMsgQueueElement.msgType {
				case MsgTypeHeartBeatRequest:
					msgAsHeartBeatRequest = recvMsgQueueElement.msg.(*HeartBeatRequestStruct)
					if msgAsHeartBeatRequest.LeaderTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsHeartBeatRequest.LeaderTerm == globals.currentTerm {
						// Unexpected... so convert to Candidate state
						msgAsHeartBeatResponse = &HeartBeatResponseStruct{MsgType: MsgTypeHeartBeatResponse, CurrentTerm: globals.currentTerm, Nonce: msgAsHeartBeatRequest.Nonce, Success: false}
						_, err = sendMsg(peer, msgAsHeartBeatResponse)
						if nil != err {
							panic(err)
						}
						globals.nextState = doCandidate
						return
					} else { // msgAsHeartBeatRequest.LeaderTerm > globals.currentTerm
						globals.currentTerm = msgAsHeartBeatRequest.LeaderTerm
						// We missed a subsequent election, so convert to Follower state
						globals.currentLeader = peer
						msgAsHeartBeatResponse = &HeartBeatResponseStruct{MsgType: MsgTypeHeartBeatResponse, CurrentTerm: globals.currentTerm, Nonce: msgAsHeartBeatRequest.Nonce, Success: true}
						_, err = sendMsg(peer, msgAsHeartBeatResponse)
						if nil != err {
							panic(err)
						}
						globals.nextState = doFollower
						return
					}
				case MsgTypeHeartBeatResponse:
					msgAsHeartBeatResponse = recvMsgQueueElement.msg.(*HeartBeatResponseStruct)
					if msgAsHeartBeatResponse.CurrentTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsHeartBeatResponse.CurrentTerm == globals.currentTerm {
						if heartbeatNonce == msgAsHeartBeatResponse.Nonce {
							_, ok = awaitingResponses[peer]
							if ok {
								delete(awaitingResponses, peer)
								if msgAsHeartBeatResponse.Success {
									heartbeatSuccessfulResponses++
								} else {
									// Unexpected... so convert to Follower state
									globals.nextState = doFollower
									return
								}
							}
						} else {
							// Ignore it
						}
					} else { // msgAsHeartBeatResponse.CurrentTerm > globals.currentTerm
						globals.currentTerm = msgAsHeartBeatResponse.CurrentTerm
						// Convert to Follower state
						globals.nextState = doFollower
						return
					}
				case MsgTypeRequestVoteRequest:
					msgAsRequestVoteRequest = recvMsgQueueElement.msg.(*RequestVoteRequestStruct)
					if msgAsRequestVoteRequest.CandidateTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsRequestVoteRequest.CandidateTerm == globals.currentTerm {
						// Ignore it
					} else { // msgAsRequestVoteRequest.CandidateTerm > globals.currentTerm
						globals.currentTerm = msgAsRequestVoteRequest.CandidateTerm
						// Abandon our Leadership, vote yes, and convert to Follower
						globals.currentLeader = nil
						globals.currentVote = peer
						msgAsRequestVoteResponse = &RequestVoteResponseStruct{MsgType: MsgTypeRequestVoteResponse, CurrentTerm: globals.currentTerm, VoteGranted: true}
						_, err = sendMsg(peer, msgAsRequestVoteResponse)
						if nil != err {
							panic(err)
						}
						globals.nextState = doFollower
						return
					}
				case MsgTypeRequestVoteResponse:
					msgAsRequestVoteResponse = recvMsgQueueElement.msg.(*RequestVoteResponseStruct)
					if msgAsRequestVoteResponse.CurrentTerm < globals.currentTerm {
						// Ignore it
					} else if msgAsRequestVoteResponse.CurrentTerm == globals.currentTerm {
						// Ignore it
					} else { // msgAsRequestVoteResponse.CurrentTerm > globals.currentTerm
						globals.currentTerm = msgAsRequestVoteResponse.CurrentTerm
						// Unexpected... so convert to Follower state
						globals.nextState = doFollower
						return
					}
				default:
					err = fmt.Errorf("Unexpected recvMsgQueueElement.msg: %v", reflect.TypeOf(recvMsgQueueElement.msg))
					panic(err)
				}
			}
		case <-time.After(heartbeatDurationRemaining):
			if heartbeatSuccessfulResponses >= heartbeatSuccessfulResponsesRequiredForQuorum {
				// Just loop back and issue a fresh HeartBeat
			} else {
				// Quorum lost... convert to Candidate state
				globals.nextState = doCandidate
				return
			}
		}
	}
}
