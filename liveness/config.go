package liveness

import (
	"crypto/rand"
	"fmt"
	"hash/crc64"
	"net"
	"sync"
	"time"

	"github.com/swiftstack/ProxyFS/conf"
	"github.com/swiftstack/ProxyFS/logger"
	"github.com/swiftstack/ProxyFS/transitions"
)

const (
	PrivateClusterUDPPortDefault = uint16(8123)

	UDPPacketSizeMin = uint64(1000) // Presumably >> udpPacketHeaderSize
	UDPPacketSizeMax = uint64(8000) // Presumably >> udpPacketHeaderSize

	UDPPacketSendSizeDefault = uint64(1400)
	UDPPacketRecvSizeDefault = uint64(1500)

	UDPPacketCapPerMessageMin = uint8(1)
	UDPPacketCapPerMessageMax = uint8(10)

	UDPPacketCapPerMessageDefault = uint8(5)

	HeartBeatDurationDefault = "1s"

	HeartBeatMissLimitMin     = uint64(2)
	HeartBeatMissLimitDefault = uint64(3)

	LogLevelNone           = uint64(0)
	LogLevelStateChanges   = uint64(1)
	LogLevelMessages       = uint64(2)
	LogLevelMessageDetails = uint64(3)
	LogLevelMax            = uint64(4)

	LogLevelDefault = LogLevelNone
)

// Each UDP Packet Header is made up of (also in LittleEndian byte order):
//   CRC64       uint64
//   MsgNonce    uint64
//   PacketIndex uint8
//   PacketCount uint8

const udpPacketHeaderSize uint64 = 8 + 8 + 1 + 1 // sizeof(CRC64) + sizeof(MsgNonce) + sizeof(PacketIndex) + sizeof(PacketCount)

// Every msg is JSON-encoded

type MsgType uint8

const (
	MsgTypeHeartBeatRequest MsgType = iota + 1 // Skip zero to avoid msg's missing the MsgType field
	MsgTypeHeartBeatResponse
	MsgTypeRequestVoteRequest
	MsgTypeRequestVoteResponse
)

type MsgTypeStruct struct {
	MsgType MsgType
}

type HeartBeatRequestStruct struct {
	MsgType    MsgType // == MsgTypeHeartBeatRequest
	LeaderTerm uint64
	Nonce      uint64
}

type HeartBeatResponseStruct struct {
	MsgType     MsgType // == MsgTypeHeartBeatResponse
	CurrentTerm uint64
	Nonce       uint64
	Success     bool
}

type RequestVoteRequestStruct struct {
	MsgType       MsgType // == MsgTypeRequestVoteRequest
	CandidateTerm uint64
}

type RequestVoteResponseStruct struct {
	MsgType     MsgType // == MsgTypeRequestVoteResponse
	CurrentTerm uint64
	VoteGranted bool
}

type recvMsgQueueElementStruct struct {
	next    *recvMsgQueueElementStruct
	prev    *recvMsgQueueElementStruct
	peer    *peerStruct
	msgType MsgType     // Even though it's inside msg, make it easier to decode
	msg     interface{} // Must be a pointer to one of the above Msg structs (other than CommonMsgHeaderStruct)
}

type volumeStruct struct {
	name          string
	state         string // One of const State{Alive|Dead|Unknown}
	lastCheckTime time.Time
}

type volumeGroupStruct struct {
	name      string
	volumeMap map[string]*volumeStruct // Key == volumeStruct.name
}

type peerStruct struct {
	name                    string
	udpAddr                 *net.UDPAddr
	curRecvMsgNonce         uint64
	curRecvPacketCount      uint8
	curRecvPacketSumSize    uint64
	curRecvPacketMap        map[uint8][]byte           // Key is PacketIndex
	prevRecvMsgQueueElement *recvMsgQueueElementStruct // Protected by globalsStruct.sync.Mutex
	//                                                    Note: Since there is only a single pointer here,
	//                                                          the total number of buffered received msgs
	//                                                          is capped by the number of listed peers
	volumeGroupMap map[string]*volumeGroupStruct // Key == volumeGroupStruct.name
}

type internalVolumeReportStruct struct {
	name          string
	state         string // One of const State{Alive|Dead|Unknown}
	lastCheckTime time.Time
}

type internalVolumeGroupReportStruct struct {
	name   string
	volume map[string]*internalVolumeReportStruct // Key = internalVolumeReportStruct.name
}

type internalServingPeerReportStruct struct {
	name        string
	volumeGroup map[string]*internalVolumeGroupReportStruct // Key = internalVolumeGroupReportStruct.name
}

type internalObservingPeerReportStruct struct {
	name        string
	servingPeer map[string]*internalServingPeerReportStruct // Key = internalServingPeerReportStruct.name
}

type internalReportStruct struct {
	observingPeer map[string]*internalObservingPeerReportStruct // Key = internalObservingPeerReportStruct.name
}

type globalsStruct struct {
	sync.Mutex               // Protects all of globalsStruct as well as peerStruct.prevRecvMsgQueueElement
	active                   bool
	whoAmI                   string
	myUDPAddr                *net.UDPAddr
	myUDPConn                *net.UDPConn
	myVolumeGroupMap         map[string]*volumeGroupStruct // Key == volumeGroupStruct.name
	peers                    map[string]*peerStruct        // Key == peerStruct.udpAddr.String() (~= peerStruct.tuple)
	udpPacketSendSize        uint64
	udpPacketSendPayloadSize uint64
	udpPacketRecvSize        uint64
	udpPacketRecvPayloadSize uint64
	udpPacketCapPerMessage   uint8
	sendMsgMessageSizeMax    uint64
	heartbeatDuration        time.Duration
	heartbeatMissLimit       uint64
	heartbeatMissDuration    time.Duration
	logLevel                 uint64
	crc64ECMATable           *crc64.Table
	nextNonce                uint64 // Randomly initialized... skips 0
	recvMsgsDoneChan         chan struct{}
	recvMsgQueueHead         *recvMsgQueueElementStruct
	recvMsgQueueTail         *recvMsgQueueElementStruct
	recvMsgChan              chan struct{}
	currentLeader            *peerStruct
	currentVote              *peerStruct
	currentTerm              uint64
	nextState                func()
	stopStateMachineChan     chan struct{}
	stateMachineStopped      bool
	stateMachineDone         sync.WaitGroup
	myObservingPeerReport    *internalObservingPeerReportStruct
	livenessReport           *internalReportStruct
}

var globals globalsStruct

func init() {
	transitions.Register("liveness", &globals)
}

func (dummy *globalsStruct) Up(confMap conf.ConfMap) (err error) {
	var (
		u64RandBuf []byte
	)

	// Ensure API behavior is disabled at startup

	globals.active = false

	// Do one-time initialization

	globals.crc64ECMATable = crc64.MakeTable(crc64.ECMA)

	u64RandBuf = make([]byte, 8)
	_, err = rand.Read(u64RandBuf)
	if nil != err {
		err = fmt.Errorf("read.Rand() failed: %v", err)
		return
	}
	globals.nextNonce = deserializeU64LittleEndian(u64RandBuf)
	if 0 == globals.nextNonce {
		globals.nextNonce = 1
	}

	err = nil
	return
}

func (dummy *globalsStruct) VolumeGroupCreated(confMap conf.ConfMap, volumeGroupName string, activePeer string, virtualIPAddr string) (err error) {
	return nil
}
func (dummy *globalsStruct) VolumeGroupMoved(confMap conf.ConfMap, volumeGroupName string, activePeer string, virtualIPAddr string) (err error) {
	return nil
}
func (dummy *globalsStruct) VolumeGroupDestroyed(confMap conf.ConfMap, volumeGroupName string) (err error) {
	return nil
}
func (dummy *globalsStruct) VolumeCreated(confMap conf.ConfMap, volumeName string, volumeGroupName string) (err error) {
	return nil
}
func (dummy *globalsStruct) VolumeMoved(confMap conf.ConfMap, volumeName string, volumeGroupName string) (err error) {
	return nil
}
func (dummy *globalsStruct) VolumeDestroyed(confMap conf.ConfMap, volumeName string) (err error) {
	return nil
}
func (dummy *globalsStruct) ServeVolume(confMap conf.ConfMap, volumeName string) (err error) {
	return nil
}
func (dummy *globalsStruct) UnserveVolume(confMap conf.ConfMap, volumeName string) (err error) {
	return nil
}

// SignaledStart will be used to halt the cluster leadership process. This is to support
// SIGHUP handling incorporates all confMap changes are incorporated... not just during a restart.
func (dummy *globalsStruct) SignaledStart(confMap conf.ConfMap) (err error) {
	// Disable API behavior as we enter the SIGHUP-handling state

	globals.active = false

	// Stop state machine

	globals.stopStateMachineChan <- struct{}{}

	globals.stateMachineDone.Wait()

	// Shut off recvMsgs()

	err = globals.myUDPConn.Close()
	if nil != err {
		logger.Errorf("liveness.globals.myUDPConn.Close() failed: %v", err)
	}

	for {
		select {
		case <-globals.recvMsgChan:
			// Just discard it
		case <-globals.recvMsgsDoneChan:
			// Since recvMsgs() exited, we are done deactivating
			err = nil
			return
		}
	}
}

// SignaledFinish will be used to kick off the cluster leadership process. This is to support
// SIGHUP handling incorporates all confMap changes are incorporated... not just during a restart.
func (dummy *globalsStruct) SignaledFinish(confMap conf.ConfMap) (err error) {
	var (
		heartbeatDuration             string
		myTuple                       string
		peer                          string
		peers                         []string
		peerTuples                    []string
		privateClusterUDPPortAsString string
		privateClusterUDPPortAsUint64 uint16
		privateIPAddr                 string
	)

	// Fetch cluster parameters

	privateClusterUDPPortAsUint64, err = confMap.FetchOptionValueUint16("Cluster", "PrivateClusterUDPPort")
	if nil != err {
		privateClusterUDPPortAsUint64 = PrivateClusterUDPPortDefault // TODO: Eventually just return
	}
	privateClusterUDPPortAsString = fmt.Sprintf("%d", privateClusterUDPPortAsUint64)

	globals.whoAmI, err = confMap.FetchOptionValueString("Cluster", "WhoAmI")
	if nil != err {
		return
	}

	privateIPAddr, err = confMap.FetchOptionValueString("Peer:"+globals.whoAmI, "PrivateIPAddr")
	if nil != err {
		return
	}

	myTuple = net.JoinHostPort(privateIPAddr, privateClusterUDPPortAsString)

	globals.myUDPAddr, err = net.ResolveUDPAddr("udp", myTuple)
	if nil != err {
		err = fmt.Errorf("Cannot parse myTuple (%s): %v", myTuple, err)
		return
	}

	globals.myUDPConn, err = net.ListenUDP("udp", globals.myUDPAddr)
	if nil != err {
		err = fmt.Errorf("Cannot bind to myTuple (%v): %v", globals.myUDPAddr, err)
		return
	}

	globals.myVolumeGroupMap = make(map[string]*volumeGroupStruct)

	peers, err = confMap.FetchOptionValueStringSlice("Cluster", "Peers")
	if nil != err {
		return
	}

	if 1 < len(peers) {
		peerTuples = make([]string, 0, len(peers)-1)

		for _, peer = range peers {
			if peer != globals.whoAmI {
				privateIPAddr, err = confMap.FetchOptionValueString("Peer:"+peer, "PrivateIPAddr")
				if nil != err {
					return
				}

				peerTuples = append(peerTuples, net.JoinHostPort(privateIPAddr, privateClusterUDPPortAsString))
			}
		}
	} else {
		peerTuples = make([]string, 0)
	}

	globals.udpPacketSendSize, err = confMap.FetchOptionValueUint64("Cluster", "UDPPacketSendSize")
	if nil != err {
		globals.udpPacketSendSize = UDPPacketSendSizeDefault // TODO: Eventually just return
	}
	if (globals.udpPacketSendSize < UDPPacketSizeMin) || (globals.udpPacketSendSize > UDPPacketSizeMax) {
		err = fmt.Errorf("udpPacketSendSize (%v) must be between %v and %v (inclusive)", globals.udpPacketSendSize, UDPPacketSizeMin, UDPPacketSizeMax)
		return
	}

	globals.udpPacketSendPayloadSize = globals.udpPacketSendSize - udpPacketHeaderSize

	globals.udpPacketRecvSize, err = confMap.FetchOptionValueUint64("Cluster", "UDPPacketRecvSize")
	if nil != err {
		globals.udpPacketRecvSize = UDPPacketRecvSizeDefault // TODO: Eventually just return
	}
	if (globals.udpPacketRecvSize < UDPPacketSizeMin) || (globals.udpPacketRecvSize > UDPPacketSizeMax) {
		err = fmt.Errorf("udpPacketRecvSize (%v) must be between %v and %v (inclusive)", globals.udpPacketRecvSize, UDPPacketSizeMin, UDPPacketSizeMax)
		return
	}

	globals.udpPacketRecvPayloadSize = globals.udpPacketRecvSize - udpPacketHeaderSize

	globals.udpPacketCapPerMessage, err = confMap.FetchOptionValueUint8("Cluster", "UDPPacketCapPerMessage")
	if nil != err {
		globals.udpPacketCapPerMessage = UDPPacketCapPerMessageDefault // TODO: Eventually just return
	}
	if (globals.udpPacketCapPerMessage < UDPPacketCapPerMessageMin) || (globals.udpPacketCapPerMessage > UDPPacketCapPerMessageMax) {
		err = fmt.Errorf("udpPacketCapPerMessage (%v) must be between %v and %v (inclusive)", globals.udpPacketCapPerMessage, UDPPacketCapPerMessageMin, UDPPacketCapPerMessageMax)
		return
	}

	globals.sendMsgMessageSizeMax = uint64(globals.udpPacketCapPerMessage) * globals.udpPacketSendPayloadSize

	heartbeatDuration, err = confMap.FetchOptionValueString("Cluster", "HeartBeatDuration")
	if nil != err {
		heartbeatDuration = HeartBeatDurationDefault // TODO: Eventually just return
	}
	globals.heartbeatDuration, err = time.ParseDuration(heartbeatDuration)
	if nil != err {
		err = fmt.Errorf("heartbeatDuration (%s) parsing error: %v", heartbeatDuration, err)
		return
	}
	if time.Duration(0) == globals.heartbeatDuration {
		err = fmt.Errorf("heartbeatDuration must be non-zero")
		return
	}

	globals.heartbeatMissLimit, err = confMap.FetchOptionValueUint64("Cluster", "HeartBeatMissLimit")
	if nil != err {
		globals.heartbeatMissLimit = HeartBeatMissLimitDefault // TODO: Eventually just return
	}
	if globals.heartbeatMissLimit < HeartBeatMissLimitMin {
		err = fmt.Errorf("heartbeatMissLimit (%v) must be at least %v", globals.heartbeatMissLimit, HeartBeatMissLimitMin)
		return
	}

	globals.heartbeatMissDuration = time.Duration(globals.heartbeatMissLimit) * globals.heartbeatDuration

	// Set LogLevel as specified or use default

	globals.logLevel, err = confMap.FetchOptionValueUint64("Cluster", "LogLevel")
	if nil != err {
		globals.logLevel = LogLevelDefault
	}
	if globals.logLevel > LogLevelMax {
		err = fmt.Errorf("logLevel (%v) must be between 0 and %v (inclusive)", globals.logLevel, LogLevelMax)
		return
	}

	// Initialize remaining globals

	err = initializeGlobalsOldWay(
		myTuple,
		peerTuples)
	if nil != err {
		err = fmt.Errorf("liveness.initializeGlobals() failed: %v", err)
		return
	}

	globals.recvMsgQueueHead = nil
	globals.recvMsgQueueTail = nil

	globals.recvMsgChan = make(chan struct{})

	globals.recvMsgsDoneChan = make(chan struct{})
	go recvMsgs()

	globals.currentLeader = nil
	globals.currentVote = nil
	globals.currentTerm = 0

	globals.nextState = doFollower

	globals.stopStateMachineChan = make(chan struct{})

	globals.stateMachineStopped = false

	// Initialize internal Liveness Report data as being empty

	globals.myObservingPeerReport = nil
	globals.livenessReport = nil

	// Become an active participant in the cluster

	globals.stateMachineDone.Add(1)
	go stateMachine()

	// Enable API behavior as we leave the SIGHUP-handling state

	globals.active = true

	err = nil
	return
}

func initializeGlobalsOldWay(myTuple string, peerTuples []string) (err error) {
	var (
		ok        bool
		peer      *peerStruct
		peerTuple string
	)

	globals.peers = make(map[string]*peerStruct)

	for _, peerTuple = range peerTuples {
		peer = &peerStruct{
			curRecvMsgNonce:         0,
			curRecvPacketCount:      0,
			curRecvPacketSumSize:    0,
			curRecvPacketMap:        nil,
			prevRecvMsgQueueElement: nil,
		}
		peer.udpAddr, err = net.ResolveUDPAddr("udp", peerTuple)
		if nil != err {
			err = fmt.Errorf("Cannot parse peerTuple (%s): %v", peerTuple, err)
			return
		}
		if globals.myUDPAddr.String() == peer.udpAddr.String() {
			err = fmt.Errorf("peerTuples must not contain myTuple (%v)", globals.myUDPAddr)
			return
		}
		_, ok = globals.peers[peer.udpAddr.String()]
		if ok {
			err = fmt.Errorf("peerTuples must not contain duplicate peers (%v)", peer.udpAddr)
			return
		}
		globals.peers[peer.udpAddr.String()] = peer
	}

	err = nil
	return
}

func (dummy *globalsStruct) Down(confMap conf.ConfMap) (err error) {
	return nil
}
