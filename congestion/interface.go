// Package congestion lets an application supply the congestion controller of a
// connection, see quic.Config.CongestionControl.
//
// The interface is the one of github.com/apernet/quic-go, so that controllers
// written for that fork work unchanged.
package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/monotime"
)

type (
	ByteCount    protocol.ByteCount
	PacketNumber protocol.PacketNumber
)

// Constants from the protocol package that a congestion controller may need.
const (
	InitialPacketSize          = protocol.InitialPacketSize
	MinPacingDelay             = protocol.MinPacingDelay
	MaxPacketBufferSize        = protocol.MaxPacketBufferSize
	MinInitialPacketSize       = protocol.MinInitialPacketSize
	MaxCongestionWindowPackets = protocol.MaxCongestionWindowPackets
	PacketsPerConnectionID     = protocol.PacketsPerConnectionID
)

type AckedPacketInfo struct {
	PacketNumber PacketNumber
	BytesAcked   ByteCount
	ReceivedTime monotime.Time
}

type LostPacketInfo struct {
	PacketNumber PacketNumber
	BytesLost    ByteCount
}

// A CongestionControl decides when and how much a connection may send.
// All methods are called from the connection's run loop.
type CongestionControl interface {
	SetRTTStatsProvider(provider RTTStatsProvider)
	TimeUntilSend(bytesInFlight ByteCount) monotime.Time
	HasPacingBudget(now monotime.Time) bool
	OnPacketSent(sentTime monotime.Time, bytesInFlight ByteCount, packetNumber PacketNumber, bytes ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight ByteCount) bool
	MaybeExitSlowStart()
	OnPacketAcked(number PacketNumber, ackedBytes ByteCount, priorInFlight ByteCount, eventTime monotime.Time)
	OnCongestionEvent(number PacketNumber, lostBytes ByteCount, priorInFlight ByteCount)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(size ByteCount)
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() ByteCount
}

// A CongestionControlEx is additionally told, once per received ACK or loss
// timer, which packets were acknowledged and which were declared lost.
type CongestionControlEx interface {
	CongestionControl
	OnCongestionEventEx(priorInFlight ByteCount, eventTime monotime.Time, ackedPackets []AckedPacketInfo, lostPackets []LostPacketInfo)
}

type RTTStatsProvider interface {
	MinRTT() time.Duration
	LatestRTT() time.Duration
	SmoothedRTT() time.Duration
	MeanDeviation() time.Duration
	MaxAckDelay() time.Duration
	PTO(includeMaxAckDelay bool) time.Duration
	UpdateRTT(sendDelta, ackDelay time.Duration)
	SetMaxAckDelay(mad time.Duration)
	SetInitialRTT(t time.Duration)
}
