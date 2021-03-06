package sortedmap

import (
	"encoding/binary"
	"fmt"
	"testing"
)

const specificBPlusTreeTestNumKeysMaxSmall = uint64(4)

type logSegmentChunkStruct struct {
	startingOffset uint64
	chunkByteSlice []byte
}

type specificBPlusTreeTestContextStruct struct {
	t                             *testing.T
	lastLogSegmentNumberGenerated uint64
	lastLogOffsetGenerated        uint64
	logSegmentChunkMap            map[uint64]*logSegmentChunkStruct // Key == logSegmentNumber (only 1 chunk stored per LogSegment)
}

type valueStruct struct {
	u32 uint32
	s8  [8]byte
}

func (context *specificBPlusTreeTestContextStruct) GetNode(logSegmentNumber uint64, logOffset uint64, logLength uint64) (nodeByteSlice []byte, err error) {
	logSegmentChunk, ok := context.logSegmentChunkMap[logSegmentNumber]

	if !ok {
		err = fmt.Errorf("logSegmentNumber not found")
		return
	}

	if logSegmentChunk.startingOffset != logOffset {
		err = fmt.Errorf("logOffset not found")
		return
	}

	if uint64(len(logSegmentChunk.chunkByteSlice)) != logLength {
		err = fmt.Errorf("logLength not found")
		return
	}

	nodeByteSlice = logSegmentChunk.chunkByteSlice

	err = nil
	return
}

func (context *specificBPlusTreeTestContextStruct) PutNode(nodeByteSlice []byte) (logSegmentNumber uint64, logOffset uint64, err error) {
	context.lastLogSegmentNumberGenerated++
	logSegmentNumber = context.lastLogSegmentNumberGenerated

	context.lastLogOffsetGenerated += logSegmentNumber + uint64(len(nodeByteSlice))
	logOffset = context.lastLogOffsetGenerated

	logSegmentChunk := &logSegmentChunkStruct{
		startingOffset: logOffset,
		chunkByteSlice: nodeByteSlice,
	}

	context.logSegmentChunkMap[logSegmentNumber] = logSegmentChunk

	err = nil
	return
}

func (context *specificBPlusTreeTestContextStruct) DiscardNode(logSegmentNumber uint64, logOffset uint64, logLength uint64) (err error) {
	logSegmentChunk, ok := context.logSegmentChunkMap[logSegmentNumber]
	if !ok {
		err = fmt.Errorf("logSegmentNumber not found")
		return
	}

	if logSegmentChunk.startingOffset != logOffset {
		err = fmt.Errorf("logOffset not found")
		return
	}

	if uint64(len(logSegmentChunk.chunkByteSlice)) != logLength {
		err = fmt.Errorf("logLength not found")
		return
	}

	delete(context.logSegmentChunkMap, logSegmentNumber)

	err = nil
	return
}

func (context *specificBPlusTreeTestContextStruct) DumpKey(key Key) (keyAsString string, err error) {
	keyAsUint32, ok := key.(uint32)
	if !ok {
		context.t.Fatalf("DumpKey() argument not an uint32")
	}
	keyAsString = fmt.Sprintf("0x%08X", keyAsUint32)
	err = nil
	return
}

func (context *specificBPlusTreeTestContextStruct) PackKey(key Key) (packedKey []byte, err error) {
	keyAsUint32, ok := key.(uint32)
	if !ok {
		context.t.Fatalf("PackKey() argument not a uint32")
	}
	packedKey = make([]byte, 4)
	binary.LittleEndian.PutUint32(packedKey, keyAsUint32)
	err = nil
	return
}

func (context *specificBPlusTreeTestContextStruct) UnpackKey(packedKey []byte) (key Key, bytesConsumed uint64, err error) {
	if 4 > len(packedKey) {
		context.t.Fatalf("UnpackKey() called with insufficient packedKey size")
	}
	keyAsUint32 := binary.LittleEndian.Uint32(packedKey[:4])
	key = keyAsUint32
	bytesConsumed = 4
	err = nil
	return
}

func (context *specificBPlusTreeTestContextStruct) DumpValue(value Value) (valueAsString string, err error) {
	valueAsValueStruct, ok := value.(valueStruct)
	if !ok {
		context.t.Fatalf("DumpValue() argument not a valueStruct")
	}
	valueAsString = fmt.Sprintf(
		"{u32: 0x%08X, s8: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X}",
		valueAsValueStruct.u32,
		valueAsValueStruct.s8[0],
		valueAsValueStruct.s8[1],
		valueAsValueStruct.s8[2],
		valueAsValueStruct.s8[3],
		valueAsValueStruct.s8[4],
		valueAsValueStruct.s8[5],
		valueAsValueStruct.s8[6],
		valueAsValueStruct.s8[7])
	err = nil
	return
}

func (context *specificBPlusTreeTestContextStruct) PackValue(value Value) (packedValue []byte, err error) {
	valueAsValueStruct, ok := value.(valueStruct)
	if !ok {
		context.t.Fatalf("PackValue() argument not a valueStruct")
	}
	u32Packed := make([]byte, 4)
	binary.LittleEndian.PutUint32(u32Packed, valueAsValueStruct.u32)
	packedValue = make([]byte, 0, 12)
	packedValue = append(packedValue, u32Packed...)
	packedValue = append(packedValue, valueAsValueStruct.s8[:]...)
	err = nil
	return
}

func (context *specificBPlusTreeTestContextStruct) UnpackValue(packedValue []byte) (value Value, bytesConsumed uint64, err error) {
	if 12 > len(packedValue) {
		context.t.Fatalf("UnpackValue() called with insufficient packedValue size")
	}
	valueAsUint32 := binary.LittleEndian.Uint32(packedValue[:4])
	var s8AsArray [8]byte
	copy(s8AsArray[:], packedValue[4:12])
	value = valueStruct{u32: valueAsUint32, s8: s8AsArray}
	bytesConsumed = 12
	err = nil
	return
}

func uint32To8ReplicaByteArray(u32 uint32) (b8 [8]byte) {
	// Assumes u32 < 0x100

	for i := 0; i < 8; i++ {
		b8[i] = byte(u32)
	}

	return
}

func TestBPlusTreeSpecific(t *testing.T) {
	var (
		btreeCacheNew              BPlusTreeCache
		btreeCacheOld              BPlusTreeCache
		btreeLen                   int
		btreeNew                   BPlusTree
		btreeOld                   BPlusTree
		err                        error
		layoutReportExpected       LayoutReport
		layoutReportReturned       LayoutReport
		logSegmentBytesExpected    uint64
		logSegmentBytesReturned    uint64
		logSegmentChunk            *logSegmentChunkStruct
		logSegmentNumber           uint64
		ok                         bool
		persistentContext          *specificBPlusTreeTestContextStruct
		rootObjectNumberFromFetch  uint64
		rootObjectNumberFromFlush  uint64
		rootObjectOffsetFromFetch  uint64
		rootObjectOffsetFromFlush  uint64
		rootObjectLengthFromFetch  uint64
		rootObjectLengthFromFlush  uint64
		valueAsValueStructExpected valueStruct
		valueAsValueStructReturned valueStruct
		valueAsValueStructToInsert valueStruct
		valueAsValueReturned       Value
	)

	persistentContext = &specificBPlusTreeTestContextStruct{t: t, lastLogSegmentNumberGenerated: 0, lastLogOffsetGenerated: 0, logSegmentChunkMap: make(map[uint64]*logSegmentChunkStruct)}

	btreeCacheNew = NewBPlusTreeCache(100, 200)

	btreeNew = NewBPlusTree(specificBPlusTreeTestNumKeysMaxSmall, CompareUint32, persistentContext, btreeCacheNew)

	rootObjectNumberFromFetch, rootObjectOffsetFromFetch, rootObjectLengthFromFetch = btreeNew.FetchLocation()
	if uint64(0) != rootObjectNumberFromFetch {
		t.Fatalf("btreeNew.FetchLocation() returned non-zero rootObjectNumber")
	}
	if uint64(0) != rootObjectOffsetFromFetch {
		t.Fatalf("btreeNew.FetchLocation() returned non-zero rootObjectOffset")
	}
	if uint64(0) != rootObjectLengthFromFetch {
		t.Fatalf("btreeNew.FetchLocation() returned non-zero rootObjectLength")
	}

	valueAsValueStructToInsert = valueStruct{u32: 5, s8: uint32To8ReplicaByteArray(5)}
	ok, err = btreeNew.Put(uint32(5), valueAsValueStructToInsert)
	if nil != err {
		t.Fatalf("btreeNew.Put(uint32(5) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeNew.Put(uint32(5), valueAsValueStructToInsert).ok should have been true")
	}

	valueAsValueStructToInsert = valueStruct{u32: 3, s8: uint32To8ReplicaByteArray(3)}
	ok, err = btreeNew.Put(uint32(3), valueAsValueStructToInsert)
	if nil != err {
		t.Fatalf("btreeNew.Put(uint32(3) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeNew.Put(uint32(3), valueAsValueStructToInsert).ok should have been true")
	}

	valueAsValueStructToInsert = valueStruct{u32: 7, s8: uint32To8ReplicaByteArray(7)}
	ok, err = btreeNew.Put(uint32(7), valueAsValueStructToInsert)
	if nil != err {
		t.Fatalf("btreeNew.Put(uint32(7) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeNew.Put(uint32(7), valueAsValueStructToInsert)).ok should have been true")
	}

	rootObjectNumberFromFlush, rootObjectOffsetFromFlush, rootObjectLengthFromFlush, err = btreeNew.Flush(false)
	if nil != err {
		t.Fatalf("btreeNew.Flush(false) should not have failed")
	}

	rootObjectNumberFromFetch, rootObjectOffsetFromFetch, rootObjectLengthFromFetch = btreeNew.FetchLocation()
	if rootObjectNumberFromFlush != rootObjectNumberFromFetch {
		t.Fatalf("btreeNew.FetchLocation() returned unexpected rootObjectNumber")
	}
	if rootObjectOffsetFromFlush != rootObjectOffsetFromFetch {
		t.Fatalf("btreeNew.FetchLocation() returned unexpected rootObjectOffset")
	}
	if rootObjectLengthFromFlush != rootObjectLengthFromFetch {
		t.Fatalf("btreeNew.FetchLocation() returned unexpected rootObjectLength")
	}

	valueAsValueReturned, ok, err = btreeNew.GetByKey(uint32(5))
	if nil != err {
		t.Fatalf("btreeNew.GetByKey(uint32(5)) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeNew.GetByKey(uint32(5)).ok should have been true")
	}
	valueAsValueStructReturned = valueAsValueReturned.(valueStruct)
	valueAsValueStructExpected = valueStruct{u32: 5, s8: uint32To8ReplicaByteArray(5)}
	if valueAsValueStructReturned != valueAsValueStructExpected {
		t.Fatalf("btreeNew.GetByKey(uint32(5)).value should have been valueAsValueStructExpected")
	}

	rootObjectNumberFromFlush, rootObjectOffsetFromFlush, rootObjectLengthFromFlush, err = btreeNew.Flush(true)
	if nil != err {
		t.Fatalf("btreeNew.Flush(true) should not have failed")
	}

	valueAsValueReturned, ok, err = btreeNew.GetByKey(uint32(3))
	if nil != err {
		t.Fatalf("btreeNew.GetByKey(uint32(3)) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeNew.GetByKey(uint32(3)).ok should have been true")
	}
	valueAsValueStructReturned = valueAsValueReturned.(valueStruct)
	valueAsValueStructExpected = valueStruct{u32: 3, s8: uint32To8ReplicaByteArray(3)}
	if valueAsValueStructReturned != valueAsValueStructExpected {
		t.Fatalf("btreeNew.GetByKey(uint32(3)).value should have been valueAsValueStructExpected")
	}

	layoutReportExpected = make(map[uint64]uint64)
	for logSegmentNumber, logSegmentChunk = range persistentContext.logSegmentChunkMap {
		logSegmentBytesExpected = uint64(len(logSegmentChunk.chunkByteSlice))
		layoutReportExpected[logSegmentNumber] = logSegmentBytesExpected // Note: assumes no chunks are stale
	}
	layoutReportReturned, err = btreeNew.FetchLayoutReport()
	if nil != err {
		t.Fatalf("btreeNew.FetchLayoutReport() should not have failed")
	}
	if len(layoutReportExpected) != len(layoutReportReturned) {
		t.Fatalf("btreeNew.FetchLayoutReport() returned unexpected LayoutReport")
	}
	for logSegmentNumber, logSegmentBytesReturned = range layoutReportReturned {
		logSegmentBytesExpected, ok = layoutReportExpected[logSegmentNumber]
		if (!ok) || (logSegmentBytesExpected != logSegmentBytesReturned) {
			t.Fatalf("btreeNew.FetchLayoutReport() returned unexpected LayoutReport")
		}
	}

	btreeCacheNew.UpdateLimits(200, 300)

	err = btreeNew.Purge(true)
	if nil != err {
		t.Fatalf("btreeNew.Purge(true) should not have failed")
	}

	valueAsValueReturned, ok, err = btreeNew.GetByKey(uint32(7))
	if nil != err {
		t.Fatalf("btreeNew.GetByKey(uint32(7)) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeNew.GetByKey(uint32(7)).ok should have been true")
	}
	valueAsValueStructReturned = valueAsValueReturned.(valueStruct)
	valueAsValueStructExpected = valueStruct{u32: 7, s8: uint32To8ReplicaByteArray(7)}
	if valueAsValueStructReturned != valueAsValueStructExpected {
		t.Fatalf("btreeNew.GetByKey(uint32(3)).value should have been valueAsValueStructExpected")
	}

	btreeNew = nil // Just let Go Garbage Collection have it (similating a crash/restart)

	btreeCacheOld = NewBPlusTreeCache(100, 200)

	btreeOld, err = OldBPlusTree(rootObjectNumberFromFlush, rootObjectOffsetFromFlush, rootObjectLengthFromFlush, CompareUint32, persistentContext, btreeCacheOld)
	if nil != err {
		t.Fatalf("OldBPlusTree() should not have failed")
	}

	btreeLen, err = btreeOld.Len()
	if nil != err {
		t.Fatalf("btreeOld.Len() should not have failed")
	}
	if 3 != btreeLen {
		t.Fatalf("btreeOld.Len() should have been 3")
	}

	valueAsValueReturned, ok, err = btreeOld.GetByKey(uint32(5))
	if nil != err {
		t.Fatalf("btreeOld.GetByKey(uint32(5)) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeOld.GetByKey(uint32(5)).ok should have been true")
	}
	valueAsValueStructReturned = valueAsValueReturned.(valueStruct)
	valueAsValueStructExpected = valueStruct{u32: 5, s8: uint32To8ReplicaByteArray(5)}
	if valueAsValueStructReturned != valueAsValueStructExpected {
		t.Fatalf("btreeOld.GetByKey(uint32(5)).value should have been valueAsValueStructExpected")
	}

	valueAsValueReturned, ok, err = btreeOld.GetByKey(uint32(3))
	if nil != err {
		t.Fatalf("btreeOld.GetByKey(uint32(3)) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeOld.GetByKey(uint32(3)).ok should have been true")
	}
	valueAsValueStructReturned = valueAsValueReturned.(valueStruct)
	valueAsValueStructExpected = valueStruct{u32: 3, s8: uint32To8ReplicaByteArray(3)}
	if valueAsValueStructReturned != valueAsValueStructExpected {
		t.Fatalf("btreeOld.GetByKey(uint32(3)).value should have been valueAsValueStructExpected")
	}

	valueAsValueReturned, ok, err = btreeOld.GetByKey(uint32(7))
	if nil != err {
		t.Fatalf("btreeOld.GetByKey(uint32(7)) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeOld.GetByKey(uint32(7)).ok should have been true")
	}
	valueAsValueStructReturned = valueAsValueReturned.(valueStruct)
	valueAsValueStructExpected = valueStruct{u32: 7, s8: uint32To8ReplicaByteArray(7)}
	if valueAsValueStructReturned != valueAsValueStructExpected {
		t.Fatalf("btreeOld.GetByKey(uint32(3)).value should have been valueAsValueStructExpected")
	}

	err = btreeOld.Touch()
	if nil != err {
		t.Fatalf("btreeOld.Touch() should not have failed")
	}

	err = btreeOld.Purge(false)
	if nil != err {
		t.Fatalf("btreeOld.Purge(false) [case 1] should not have failed")
	}

	err = btreeOld.Purge(true)
	if nil == err {
		t.Fatalf("btreeOld.Purge(true) [case 1] should have failed")
	}

	valueAsValueStructToInsert = valueStruct{u32: 2, s8: uint32To8ReplicaByteArray(2)}
	ok, err = btreeOld.Put(uint32(2), valueAsValueStructToInsert)
	if nil != err {
		t.Fatalf("btreeOld.Put(uint32(2) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeOld.Put(uint32(2), valueAsValueStructToInsert).ok should have been true")
	}

	valueAsValueStructToInsert = valueStruct{u32: 4, s8: uint32To8ReplicaByteArray(4)}
	ok, err = btreeOld.Put(uint32(4), valueAsValueStructToInsert)
	if nil != err {
		t.Fatalf("btreeOld.Put(uint32(4) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeOld.Put(uint32(4), valueAsValueStructToInsert).ok should have been true")
	}

	valueAsValueStructToInsert = valueStruct{u32: 6, s8: uint32To8ReplicaByteArray(6)}
	ok, err = btreeOld.Put(uint32(6), valueAsValueStructToInsert)
	if nil != err {
		t.Fatalf("btreeOld.Put(uint32(6) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeOld.Put(uint32(6), valueAsValueStructToInsert).ok should have been true")
	}

	valueAsValueStructToInsert = valueStruct{u32: 8, s8: uint32To8ReplicaByteArray(8)}
	ok, err = btreeOld.Put(uint32(8), valueAsValueStructToInsert)
	if nil != err {
		t.Fatalf("btreeOld.Put(uint32(8) should not have failed")
	}
	if !ok {
		t.Fatalf("btreeOld.Put(uint32(8), valueAsValueStructToInsert).ok should have been true")
	}

	err = btreeOld.Purge(false)
	if nil != err {
		t.Fatalf("btreeOld.Purge(false) [case 2] should not have failed")
	}

	err = btreeOld.Purge(true)
	if nil == err {
		t.Fatalf("btreeOld.Purge(true) [case 2] should have failed")
	}

	nextItemIndexToTouch, err := btreeOld.TouchItem(0)
	if nil != err {
		t.Fatalf("btreeOld.TouchItem(0) should not have failed")
	}
	if 2 != nextItemIndexToTouch {
		t.Fatalf("btreeOld.TouchItem(0) should have returned 2")
	}

	nextItemIndexToTouch, err = btreeOld.TouchItem(2)
	if nil != err {
		t.Fatalf("btreeOld.TouchItem(2) should not have failed")
	}
	if 4 != nextItemIndexToTouch {
		t.Fatalf("btreeOld.TouchItem(2) should have returned 4")
	}

	nextItemIndexToTouch, err = btreeOld.TouchItem(4)
	if nil != err {
		t.Fatalf("btreeOld.TouchItem(4) should not have failed")
	}
	if 7 != nextItemIndexToTouch {
		t.Fatalf("btreeOld.TouchItem(4) should have returned 7")
	}

	nextItemIndexToTouch, err = btreeOld.TouchItem(7)
	if nil != err {
		t.Fatalf("btreeOld.TouchItem(7) should not have failed")
	}
	if 2 != nextItemIndexToTouch {
		t.Fatalf("btreeOld.TouchItem(7) should have returned 2")
	}

	err = btreeOld.Discard()
	if nil != err {
		t.Fatalf("btreeOld.Discard() should not have failed")
	}
}
