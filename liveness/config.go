package liveness

import (
	"fmt"
	"hash/crc64"
	"net"
	"sync"
	"time"

	"github.com/swiftstack/ProxyFS/conf"
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

	UDPPacketCapPerMessageDefault = uint64(5)

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

// Every msg is cstruct-encoded in cstruct.LittleEndian byte order
// Each UDP Packet Header is made up of (also in LittleEndian byte order):
//   CRC64       uint64
//   MsgNonce    uint64
//   PacketIndex uint8
//   PacketCount uint8

const udpPacketHeaderSize uint64 = 8 + 8 + 1 + 1 // sizeof(CRC64) + sizeof(MsgNonce) + sizeof(PacketIndex) + sizeof(PacketCount)

type MsgType uint8

const (
	MsgTypeHeartBeatRequest MsgType = iota
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

type peerStruct struct {
	udpAddr                 *net.UDPAddr
	curRecvMsgNonce         uint64
	curRecvPacketCount      uint8
	curRecvPacketSumSize    uint64
	curRecvPacketMap        map[uint8][]byte           // Key is PacketIndex
	prevRecvMsgQueueElement *recvMsgQueueElementStruct // Protected by globalsStruct.sync.Mutex
	//                                                    Note: Since there is only a single pointer here,
	//                                                          the total number of buffered received msgs
	//                                                          is capped by the number of listed peers
}

type globalsStruct struct {
	sync.Mutex                 // Protects all of globalsStruct as well as peerStruct.prevRecvMsgQueueElement
	active                     bool
	myUDPAddr                  *net.UDPAddr
	myUDPConn                  *net.UDPConn
	peers                      map[string]*peerStruct // Key == peerStruct.udpAddr.String() (~= peerStruct.tuple)
	udpPacketSendSize          uint64
	udpPacketSendPayloadSize   uint64
	udpPacketRecvSize          uint64
	udpPacketRecvPayloadSize   uint64
	udpPacketCapPerMessage     uint8
	sendMsgMessageSizeMax      uint64
	heartbeatDuration          time.Duration
	heartbeatMissLimit         uint64
	heartbeatMissDuration      time.Duration
	logLevel                   uint64
	msgTypeBufSize             uint64
	heartBeatRequestBufSize    uint64
	heartBeatResponseBufSize   uint64
	requestVoteRequestBufSize  uint64
	requestVoteResponseBufSize uint64
	crc64ECMATable             *crc64.Table
	nextNonce                  uint64 // Randomly initialized... skips 0
	recvMsgsDoneChan           chan struct{}
	recvMsgQueueHead           *recvMsgQueueElementStruct
	recvMsgQueueTail           *recvMsgQueueElementStruct
	recvMsgChan                chan struct{}
	currentLeader              *peerStruct
	currentVote                *peerStruct
	currentTerm                uint64
	nextState                  func()
	stopStateMachineChan       chan struct{}
	stateMachineStopped        bool
	stateMachineDone           sync.WaitGroup
}

var globals globalsStruct

func init() {
	transitions.Register("liveness", &globals)
}

func (dummy *globalsStruct) Up(confMap conf.ConfMap) (err error) {
	// Ensure API behavior is disabled at startup
	globals.active = false
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

	// Stop participating in the cluster

	deactivateClusterParticipation()

	// All done

	err = nil
	return
}

// SignaledFinish will be used to kick off the cluster leadership process. This is to support
// SIGHUP handling incorporates all confMap changes are incorporated... not just during a restart.
func (dummy *globalsStruct) SignaledFinish(confMap conf.ConfMap) (err error) {
	var (
		heartbeatDuration             string
		heartbeatMissLimit            uint64
		logLevel                      uint64
		myTuple                       string
		peer                          string
		peers                         []string
		peerTuples                    []string
		privateClusterUDPPortAsString string
		privateClusterUDPPortAsUint64 uint16
		privateIPAddr                 string
		udpPacketCapPerMessage        uint64
		udpPacketRecvSize             uint64
		udpPacketSendSize             uint64
		whoAmI                        string
	)

	// Fetch cluster parameters

	privateClusterUDPPortAsUint64, err = confMap.FetchOptionValueUint16("Cluster", "PrivateClusterUDPPort")
	if nil != err {
		privateClusterUDPPortAsUint64 = PrivateClusterUDPPortDefault // TODO: Eventually just return
	}
	privateClusterUDPPortAsString = fmt.Sprintf("%d", privateClusterUDPPortAsUint64)

	whoAmI, err = confMap.FetchOptionValueString("Cluster", "WhoAmI")
	if nil != err {
		return
	}

	privateIPAddr, err = confMap.FetchOptionValueString("Peer:"+whoAmI, "PrivateIPAddr")
	if nil != err {
		return
	}

	myTuple = net.JoinHostPort(privateIPAddr, privateClusterUDPPortAsString)

	peers, err = confMap.FetchOptionValueStringSlice("Cluster", "Peers")
	if nil != err {
		return
	}

	if 1 < len(peers) {
		peerTuples = make([]string, 0, len(peers)-1)

		for _, peer = range peers {
			if peer != whoAmI {
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

	udpPacketSendSize, err = confMap.FetchOptionValueUint64("Cluster", "UDPPacketSendSize")
	if nil != err {
		udpPacketSendSize = UDPPacketSendSizeDefault // TODO: Eventually just return
	}
	udpPacketRecvSize, err = confMap.FetchOptionValueUint64("Cluster", "UDPPacketRecvSize")
	if nil != err {
		udpPacketRecvSize = UDPPacketRecvSizeDefault // TODO: Eventually just return
	}
	udpPacketCapPerMessage, err = confMap.FetchOptionValueUint64("Cluster", "UDPPacketCapPerMessage")
	if nil != err {
		udpPacketCapPerMessage = UDPPacketCapPerMessageDefault // TODO: Eventually just return
	}
	heartbeatDuration, err = confMap.FetchOptionValueString("Cluster", "HeartBeatDuration")
	if nil != err {
		heartbeatDuration = HeartBeatDurationDefault // TODO: Eventually just return
	}
	heartbeatMissLimit, err = confMap.FetchOptionValueUint64("Cluster", "HeartBeatMissLimit")
	if nil != err {
		heartbeatMissLimit = HeartBeatMissLimitDefault // TODO: Eventually just return
	}
	logLevel, err = confMap.FetchOptionValueUint64("Cluster", "LogLevel")
	if nil != err {
		// Just assume we want the Default (None) LogLevel
		logLevel = LogLevelDefault
	}

	// Initialize globals

	err = initializeGlobals(
		myTuple,
		peerTuples,
		udpPacketSendSize,
		udpPacketRecvSize,
		udpPacketCapPerMessage,
		heartbeatDuration,
		heartbeatMissLimit,
		logLevel)
	if nil != err {
		err = fmt.Errorf("liveness.initializeGlobals() failed: %v", err)
		return
	}

	// Become an active participant in the cluster

	activateClusterParticipation()

	// Enable API behavior as we leave the SIGHUP-handling state

	globals.active = false

	err = nil
	return
}

func (dummy *globalsStruct) Down(confMap conf.ConfMap) (err error) {
	return nil
}
