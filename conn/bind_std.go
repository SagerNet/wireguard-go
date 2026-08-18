/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type EgressProvider interface {
	SetEgressPort(port uint16) bool
	LookupEgress(destination netip.AddrPort) *net.UDPConn
	ReceiveEgress(buffer []byte) (int, netip.AddrPort, error)
}

var _ Bind = (*StdNetBind)(nil)

// StdNetBind implements Bind for all platforms. While Windows has its own Bind
// (see bind_windows.go), it may fall back to StdNetBind.
// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type StdNetBind struct {
	externalControl     control.Func
	egressProvider      EgressProvider
	onRead              func(size int)
	onWrite             func(size int)
	reservedAccess      sync.RWMutex
	reservedForEndpoint map[netip.AddrPort][3]uint8

	mu            sync.Mutex // protects all fields except as specified
	ipv4          *net.UDPConn
	ipv6          *net.UDPConn
	ipv4PC        *ipv4.PacketConn // will be nil on non-Linux
	ipv6PC        *ipv6.PacketConn // will be nil on non-Linux
	ipv4RC        syscall.RawConn  // will be nil on non-Darwin
	ipv6RC        syscall.RawConn  // will be nil on non-Darwin
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool

	msgx msgXState

	blackhole4 bool
	blackhole6 bool
}

func NewStdNetBind(externalControl control.Func) Bind {
	return &StdNetBind{
		externalControl:     externalControl,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),

		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		msgsPool: sync.Pool{
			New: func() any {
				// ipv6.Message and ipv4.Message are interchangeable as they are
				// both aliases for x/net/internal/socket.Message.
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},
	}
}

type StdNetEndpoint struct {
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current sticky source address and interface index, if
	// supported. Typically this is a PKTINFO structure from/for control
	// messages, see unix.PKTINFO for an example.
	src []byte
}

var (
	_ Bind     = (*StdNetBind)(nil)
	_ Endpoint = &StdNetEndpoint{}
)

func (*StdNetBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (e *StdNetEndpoint) ClearSrc() {
	if e.src != nil {
		// Truncate src, no need to reallocate.
		e.src = e.src[:0]
	}
}

func (e *StdNetEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

// See control_default,linux, etc for implementations of SrcIP and SrcIfidx.

func (e *StdNetEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *StdNetEndpoint) DstToString() string {
	return e.AddrPort.String()
}

func listenNet(externalControl control.Func, network string, port int) (*net.UDPConn, int, error) {
	var listenerAddr string
	if network == "udp6" {
		listenerAddr = "[::]:" + strconv.Itoa(port)
	} else {
		listenerAddr = ":" + strconv.Itoa(port)
	}

	var listener net.ListenConfig
	listener.Control = func(network, address string, conn syscall.RawConn) error {
		for _, wgControlFn := range controlFns {
			err := wgControlFn(network, address, conn)
			if err != nil {
				return err
			}
		}
		if externalControl != nil {
			return externalControl(network, address, conn)
		} else {
			return nil
		}
	}
	conn, err := listener.ListenPacket(context.Background(), network, listenerAddr)
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn.(*net.UDPConn), uaddr.Port, nil
}

func (s *StdNetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
	s.msgx.reset()

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4pc *ipv4.PacketConn
	var v6pc *ipv6.PacketConn

	v4conn, v4port, err := listenNet(s.externalControl, "udp4", port)
	if err == nil {
		port = v4port
	} else if !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	v6conn, v6port, err := listenNet(s.externalControl, "udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err == nil {
		port = v6port
	} else if !errors.Is(err, syscall.EAFNOSUPPORT) {
		v4conn.Close()
		return nil, 0, err
	}
	var fns []ReceiveFunc
	if v4conn != nil {
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v4pc = ipv4.NewPacketConn(v4conn)
			s.ipv4PC = v4pc
		}
		if supportsMsgX {
			var receiveFn ReceiveFunc
			receiveFn, err = s.makeReceiveMsgX(v4conn, false)
			if err != nil {
				v4conn.Close()
				return nil, 0, err
			}
			s.ipv4RC, err = v4conn.SyscallConn()
			if err != nil {
				v4conn.Close()
				return nil, 0, err
			}
			fns = append(fns, receiveFn)
		} else {
			fns = append(fns, s.makeReceiveIPv4(v4pc, v4conn, s.ipv4RxOffload))
		}
		s.ipv4 = v4conn
	}
	if v6conn != nil {
		s.ipv6TxOffload, s.ipv6RxOffload = supportsUDPOffload(v6conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v6pc = ipv6.NewPacketConn(v6conn)
			s.ipv6PC = v6pc
		}
		if supportsMsgX {
			var receiveFn ReceiveFunc
			receiveFn, err = s.makeReceiveMsgX(v6conn, true)
			if err != nil {
				v6conn.Close()
				return nil, 0, err
			}
			s.ipv6RC, err = v6conn.SyscallConn()
			if err != nil {
				v6conn.Close()
				return nil, 0, err
			}
			fns = append(fns, receiveFn)
		} else {
			fns = append(fns, s.makeReceiveIPv6(v6pc, v6conn, s.ipv6RxOffload))
		}
		s.ipv6 = v6conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	if s.egressProvider != nil {
		s.egressProvider.SetEgressPort(uint16(port))
		fns = append(fns, func(slab []byte, packets []ReceivedPacket) (int, error) {
			dataLength, source, err := s.egressProvider.ReceiveEgress(slab)
			if err != nil {
				return 0, err
			}
			packets[0] = ReceivedPacket{
				Size:     dataLength,
				Endpoint: &StdNetEndpoint{AddrPort: source},
			}
			return 1, nil
		})
	}
	for i, receiveFunc := range fns {
		fns[i] = func(slab []byte, packets []ReceivedPacket) (int, error) {
			count, err := receiveFunc(slab, packets)
			for _, packet := range packets[:count] {
				if packet.Size > 3 {
					clear(slab[packet.Offset+1 : packet.Offset+4])
				}
			}
			if count > 0 && s.onRead != nil {
				s.onRead(packets[0].Size)
			}
			return count, err
		}
	}

	return fns, uint16(port), nil
}

func (s *StdNetBind) SetEgressProvider(provider EgressProvider) {
	s.egressProvider = provider
}

// SetIOActivityFuncs sets callbacks invoked once per receive and send syscall batch:
// onRead with the size of the first packet of a received batch, onWrite with the size of
// the first packet of a sent batch. Call it before Open.
func (s *StdNetBind) SetIOActivityFuncs(onRead func(size int), onWrite func(size int)) {
	s.onRead = onRead
	s.onWrite = onWrite
}

// putMessages resets each message in (*msgs)[:usedMsgs] for reuse, then returns
// msgs to its [sync.Pool].
func (s *StdNetBind) putMessages(msgs *[]ipv6.Message, usedMsgs int) {
	for i := range (*msgs)[:usedMsgs] {
		// Clear references to previously used packet buffers, otherwise they
		// may never be GC'd.
		clear((*msgs)[i].Buffers)
		(*msgs)[i] = ipv6.Message{
			Buffers: (*msgs)[i].Buffers[:1], // Non-coalesced write paths require a single element.
			OOB:     (*msgs)[i].OOB[:0],
		}
	}
	s.msgsPool.Put(msgs)
}

func (s *StdNetBind) getMessages() *[]ipv6.Message {
	return s.msgsPool.Get().(*[]ipv6.Message)
}

// If compilation fails here these are no longer the same underlying type.
var _ ipv6.Message = ipv4.Message{}

type batchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

const maxDatagramSize = 1<<16 - 1

func (s *StdNetBind) receiveIP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	slab []byte,
	packets []ReceivedPacket,
) (n int, err error) {
	msgs := s.getMessages()
	usedMsgs := 1
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		// set a floor of 1 in case len(slab) < maxDatagramSize
		usedMsgs = max(1, len(slab)/maxDatagramSize)
		// we can't read more datagrams than what we can describe in packets
		usedMsgs = min(len(packets), usedMsgs)
	}
	defer s.putMessages(msgs, usedMsgs)
	var numMsgs int
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		rem := slab
		for i := range usedMsgs {
			end := maxDatagramSize
			if len(rem) < maxDatagramSize {
				end = len(rem)
			}
			(*msgs)[i].Buffers[0] = rem[:end]
			(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
			rem = rem[end:]
		}
		numMsgs, err = br.ReadBatch((*msgs)[:usedMsgs], 0)
		if err != nil {
			return 0, err
		}
	} else {
		msg := &(*msgs)[0]
		msg.Buffers[0] = slab
		msg.OOB = msg.OOB[:cap(msg.OOB)]
		msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1
	}
	return fillReceivedPackets((*msgs)[:numMsgs], maxDatagramSize, packets, rxOffload, getGSOSize)
}

func (s *StdNetBind) makeReceiveIPv4(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(slab []byte, packets []ReceivedPacket) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, slab, packets)
	}
}

func (s *StdNetBind) makeReceiveIPv6(pc *ipv6.PacketConn, conn *net.UDPConn, rxOffload bool) ReceiveFunc {
	return func(slab []byte, packets []ReceivedPacket) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, slab, packets)
	}
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return IdealBatchSize
	}
	if supportsMsgX {
		return msgXBatchSize
	}
	return 1
}

func (s *StdNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.egressProvider != nil {
		s.egressProvider.SetEgressPort(0)
	}
	var err1, err2 error
	if s.ipv4 != nil {
		err1 = s.ipv4.Close()
		s.ipv4 = nil
		s.ipv4PC = nil
	}
	if s.ipv6 != nil {
		err2 = s.ipv6.Close()
		s.ipv6 = nil
		s.ipv6PC = nil
	}
	s.blackhole4 = false
	s.blackhole6 = false
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false
	if err1 != nil {
		return err1
	}
	return err2
}

type ErrUDPGSODisabled struct {
	onLaddr  string
	RetryErr error
}

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf("disabled UDP GSO on %s, NIC(s) may not support checksum offload", e.onLaddr)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}

func (s *StdNetBind) Send(bufs [][]byte, endpoint Endpoint, offset int) error {
	for len(bufs) > IdealBatchSize {
		err := s.Send(bufs[:IdealBatchSize], endpoint, offset)
		if err != nil {
			return err
		}
		bufs = bufs[IdealBatchSize:]
	}
	if s.onWrite != nil && len(bufs) > 0 {
		s.onWrite(len(bufs[0]) - offset)
	}
	standardEndpoint := endpoint.(*StdNetEndpoint)
	s.mu.Lock()
	blackhole := s.blackhole4
	conn := s.ipv4
	offload := s.ipv4TxOffload
	br := batchWriter(s.ipv4PC)
	is6 := false
	if standardEndpoint.DstIP().Is6() {
		blackhole = s.blackhole6
		conn = s.ipv6
		br = s.ipv6PC
		is6 = true
		offload = s.ipv6TxOffload
	}
	s.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}

	msgs := s.getMessages()
	usedMsgs := len(bufs)
	defer s.putMessages(msgs, usedMsgs)
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)
	if is6 {
		as16 := standardEndpoint.DstIP().As16()
		ua.IP = append(ua.IP[:0], as16[:]...)
	} else {
		as4 := standardEndpoint.DstIP().As4()
		ua.IP = append(ua.IP[:0], as4[:]...)
	}
	ua.Port = int(standardEndpoint.Port())
	var (
		retried bool
		err     error
	)
	s.reservedAccess.RLock()
	reserved, reservedLoaded := s.reservedForEndpoint[standardEndpoint.AddrPort]
	s.reservedAccess.RUnlock()
	if reservedLoaded {
		for _, buf := range bufs {
			if len(buf) > offset+3 {
				copy(buf[offset+1:offset+4], reserved[:])
			}
		}
	}
	if s.egressProvider != nil {
		memberConn := s.egressProvider.LookupEgress(standardEndpoint.AddrPort)
		if memberConn != nil {
			for _, buf := range bufs {
				_, err = memberConn.WriteToUDPAddrPort(buf[offset:], standardEndpoint.AddrPort)
				if err != nil {
					return err
				}
			}
			return nil
		}
	}
retry:
	if offload {
		n := coalesceMessages(ua, standardEndpoint, bufs, offset, *msgs, setGSOSize)
		err = s.send(conn, br, (*msgs)[:n])
		if err != nil && offload && errShouldDisableUDPGSO(err) {
			offload = false
			s.mu.Lock()
			if is6 {
				s.ipv6TxOffload = false
			} else {
				s.ipv4TxOffload = false
			}
			s.mu.Unlock()
			retried = true
			goto retry
		}
	} else {
		for i := range bufs {
			(*msgs)[i].Addr = ua
			(*msgs)[i].Buffers[0] = bufs[i][offset:]
			setSrcControl(&(*msgs)[i].OOB, standardEndpoint)
		}
		err = s.send(conn, br, (*msgs)[:len(bufs)])
	}
	if retried {
		return ErrUDPGSODisabled{onLaddr: conn.LocalAddr().String(), RetryErr: err}
	}
	return err
}

func (s *StdNetBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	s.reservedAccess.Lock()
	s.reservedForEndpoint[destination] = reserved
	s.reservedAccess.Unlock()
}

func (s *StdNetBind) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
	} else {
		if supportsMsgX {
			return s.sendMsgX(conn, msgs)
		}
		for _, msg := range msgs {
			_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
			if err != nil {
				break
			}
		}
	}
	return err
}

const (
	// Exceeding these values results in EMSGSIZE. They account for layer3 and
	// layer4 headers. IPv6 does not need to account for itself as the payload
	// length field is self excluding.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen = 1<<16 - 1 - 8

	// This is a hard limit imposed by the kernel.
	udpSegmentMaxDatagrams = 64
)

type setGSOFunc func(control *[]byte, gsoSize uint16)

func coalesceMessages(addr *net.UDPAddr, ep *StdNetEndpoint, bufs [][]byte, offset int, msgs []ipv6.Message, setGSO setGSOFunc) int {
	var (
		base     = -1 // index of msg we are currently coalescing into
		gsoSize  int  // segmentation size of msgs[base]
		totalLen int  // length of all dgrams coalesced into msgs[base]
		dgramCnt int  // number of dgrams coalesced into msgs[base]
		endBatch bool // tracking flag to start a new batch on next iteration of bufs
	)
	maxPayloadLen := maxIPv4PayloadLen
	if ep.DstIP().Is6() {
		maxPayloadLen = maxIPv6PayloadLen
	}
	for i, buf := range bufs {
		buf = buf[offset:]
		if i > 0 {
			msgLen := len(buf)
			if msgLen+totalLen <= maxPayloadLen &&
				msgLen <= gsoSize &&
				dgramCnt < udpSegmentMaxDatagrams &&
				!endBatch {
				// Coalesce as an additional iovec instead of copying: element
				// buffers are sized to their packet and have no spare capacity.
				msgs[base].Buffers = append(msgs[base].Buffers, buf)
				totalLen += msgLen
				if i == len(bufs)-1 {
					setGSO(&msgs[base].OOB, uint16(gsoSize))
				}
				dgramCnt++
				if msgLen < gsoSize {
					// A smaller than gsoSize packet on the tail is legal, but
					// it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			setGSO(&msgs[base].OOB, uint16(gsoSize))
		}
		// Reset prior to incrementing base since we are preparing to start a
		// new potential batch.
		endBatch = false
		base++
		gsoSize = len(buf)
		totalLen = len(buf)
		setSrcControl(&msgs[base].OOB, ep)
		msgs[base].Buffers = append(msgs[base].Buffers[:0], buf)
		msgs[base].Addr = addr
		dgramCnt = 1
	}
	return base + 1
}

type getGSOFunc func(control []byte) (int, error)

func fillReceivedPackets(msgs []ipv6.Message, slabOffset int, packets []ReceivedPacket, rxOffload bool, getGSO getGSOFunc) (n int, err error) {
	for i, msg := range msgs {
		var (
			gsoSize    int
			start      int
			numToSplit = 1
		)
		if rxOffload {
			gsoSize, err = getGSO(msg.OOB[:msg.NN])
			if err != nil {
				return n, err
			}
			if gsoSize > 0 {
				numToSplit = (msg.N + gsoSize - 1) / gsoSize
			}
		}
		ep := &StdNetEndpoint{AddrPort: M.AddrPortFromNet(msg.Addr)} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		regionOffset := i * slabOffset // region may contain multiple coalesced packets
		for j := 0; j < numToSplit; j++ {
			if n >= len(packets) {
				return n, fmt.Errorf("%w: filling received packet metadata resulted in overflow", io.ErrShortBuffer)
			}
			end := msg.N
			if gsoSize > 0 && start+gsoSize < end {
				end = start + gsoSize
			}
			packets[n] = ReceivedPacket{
				Offset:   regionOffset + start,
				Size:     end - start,
				Endpoint: ep,
			}
			n++
			start = end
		}
	}
	return n, nil
}
