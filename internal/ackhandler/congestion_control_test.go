package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// plainCC is a congestion.CongestionControl that records what it is told.
type plainCC struct {
	rttStats    congestion.RTTStatsProvider
	sent        []congestion.PacketNumber
	acked, lost []congestion.PacketNumber
}

func (c *plainCC) SetRTTStatsProvider(p congestion.RTTStatsProvider) { c.rttStats = p }
func (c *plainCC) TimeUntilSend(congestion.ByteCount) monotime.Time  { return 0 }
func (c *plainCC) HasPacingBudget(monotime.Time) bool                { return true }
func (c *plainCC) CanSend(congestion.ByteCount) bool                 { return true }
func (c *plainCC) MaybeExitSlowStart()                               {}
func (c *plainCC) OnRetransmissionTimeout(bool)                      {}
func (c *plainCC) SetMaxDatagramSize(congestion.ByteCount)           {}
func (c *plainCC) InSlowStart() bool                                 { return false }
func (c *plainCC) InRecovery() bool                                  { return false }
func (c *plainCC) GetCongestionWindow() congestion.ByteCount         { return 42 * 1200 }

func (c *plainCC) OnPacketSent(_ monotime.Time, _ congestion.ByteCount, pn congestion.PacketNumber, _ congestion.ByteCount, _ bool) {
	c.sent = append(c.sent, pn)
}

func (c *plainCC) OnPacketAcked(pn congestion.PacketNumber, _, _ congestion.ByteCount, _ monotime.Time) {
	c.acked = append(c.acked, pn)
}

func (c *plainCC) OnCongestionEvent(pn congestion.PacketNumber, _, _ congestion.ByteCount) {
	c.lost = append(c.lost, pn)
}

type congestionEvent struct {
	priorInFlight congestion.ByteCount
	acked         []congestion.AckedPacketInfo
	lost          []congestion.LostPacketInfo
}

// exCC additionally records the per-ACK events of a congestion.CongestionControlEx.
type exCC struct {
	plainCC
	events []congestionEvent
}

func (c *exCC) OnCongestionEventEx(priorInFlight congestion.ByteCount, _ monotime.Time, acked []congestion.AckedPacketInfo, lost []congestion.LostPacketInfo) {
	c.events = append(c.events, congestionEvent{
		priorInFlight: priorInFlight,
		acked:         append([]congestion.AckedPacketInfo(nil), acked...),
		lost:          append([]congestion.LostPacketInfo(nil), lost...),
	})
}

func newSentPacketHandlerForCongestionControlTest(rttStats *utils.RTTStats) SentPacketHandler {
	return newSentPacketHandlerWithStats(rttStats, &utils.ConnectionStats{})
}

func newSentPacketHandlerWithStats(rttStats *utils.RTTStats, connStats *utils.ConnectionStats) SentPacketHandler {
	return NewSentPacketHandler(
		0,
		1200,
		rttStats,
		connStats,
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		nil,
		utils.DefaultLogger,
	)
}

func send1RTTPackets(sph SentPacketHandler, now monotime.Time, n int) []protocol.PacketNumber {
	var packets packetTracker
	var pns []protocol.PacketNumber
	for range n {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
		pns = append(pns, pn)
	}
	return pns
}

func TestSentPacketHandlerSuppliedCongestionControl(t *testing.T) {
	rttStats := utils.NewRTTStats()
	sph := newSentPacketHandlerForCongestionControlTest(rttStats)

	cc := &exCC{}
	var sizes []congestion.ByteCount
	sph.SetCongestionControl(func(size congestion.ByteCount) congestion.CongestionControl {
		sizes = append(sizes, size)
		return cc
	}, 1200)
	require.Equal(t, []congestion.ByteCount{1200}, sizes)
	require.Same(t, rttStats, cc.rttStats)

	now := monotime.Now()
	pns := send1RTTPackets(sph, now, 5)
	require.Len(t, cc.sent, 5)

	// Acknowledging only the last packet declares the first two lost: they
	// are three or more packet numbers behind it.
	ackTime := now.Add(10 * time.Millisecond)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, ackTime)
	require.NoError(t, err)

	require.Equal(t, []congestion.PacketNumber{congestion.PacketNumber(pns[4])}, cc.acked)
	require.Equal(t, []congestion.PacketNumber{congestion.PacketNumber(pns[0]), congestion.PacketNumber(pns[1])}, cc.lost)
	require.Equal(t, []congestionEvent{{
		priorInFlight: 5 * 1200,
		acked:         []congestion.AckedPacketInfo{{PacketNumber: congestion.PacketNumber(pns[4]), BytesAcked: 1200, ReceivedTime: ackTime}},
		lost: []congestion.LostPacketInfo{
			{PacketNumber: congestion.PacketNumber(pns[0]), BytesLost: 1200},
			{PacketNumber: congestion.PacketNumber(pns[1]), BytesLost: 1200},
		},
	}}, cc.events)

	// The remaining two packets are declared lost by the loss timer.
	lossTime := sph.GetLossDetectionTimeout()
	require.False(t, lossTime.IsZero())
	require.NoError(t, sph.OnLossDetectionTimeout(lossTime))
	require.Len(t, cc.events, 2)
	require.Equal(t, congestionEvent{
		priorInFlight: 2 * 1200,
		lost: []congestion.LostPacketInfo{
			{PacketNumber: congestion.PacketNumber(pns[2]), BytesLost: 1200},
			{PacketNumber: congestion.PacketNumber(pns[3]), BytesLost: 1200},
		},
	}, cc.events[1])
}

func TestSentPacketHandlerSuppliedCongestionControlWithoutEvents(t *testing.T) {
	sph := newSentPacketHandlerForCongestionControlTest(utils.NewRTTStats())
	cc := &plainCC{}
	sph.SetCongestionControl(func(congestion.ByteCount) congestion.CongestionControl { return cc }, 1200)

	now := monotime.Now()
	pns := send1RTTPackets(sph, now, 5)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, now.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Len(t, cc.sent, 5)
	require.Equal(t, []congestion.PacketNumber{congestion.PacketNumber(pns[4])}, cc.acked)
	require.Equal(t, []congestion.PacketNumber{congestion.PacketNumber(pns[0]), congestion.PacketNumber(pns[1])}, cc.lost)
}

// A path migration starts a new congestion controller. It has to come from the
// application again, not fall back to the built-in one.
func TestSentPacketHandlerSuppliedCongestionControlSurvivesMigration(t *testing.T) {
	sph := newSentPacketHandlerForCongestionControlTest(utils.NewRTTStats())

	var made []*exCC
	var sizes []congestion.ByteCount
	sph.SetCongestionControl(func(size congestion.ByteCount) congestion.CongestionControl {
		sizes = append(sizes, size)
		made = append(made, &exCC{})
		return made[len(made)-1]
	}, 1200)

	now := monotime.Now()
	send1RTTPackets(sph, now, 2)
	require.Len(t, made[0].sent, 2)

	sph.MigratedPath(now, 1300)
	require.Equal(t, []congestion.ByteCount{1200, 1300}, sizes)
	require.Len(t, made, 2)

	send1RTTPackets(sph, now, 3)
	require.Len(t, made[0].sent, 2)
	require.Len(t, made[1].sent, 3)
	require.Equal(t, protocol.ByteCount(42*1200), sph.(*sentPacketHandler).congestion.GetCongestionWindow())
}

// The built-in sender counts lost packets for Conn.ConnectionStats. With a
// supplied controller the count has to keep working.
func TestSentPacketHandlerSuppliedCongestionControlCountsLoss(t *testing.T) {
	for _, tc := range []struct {
		name string
		cc   congestion.CongestionControl
	}{{"with events", &exCC{}}, {"without events", &plainCC{}}} {
		t.Run(tc.name, func(t *testing.T) {
			var connStats utils.ConnectionStats
			sph := newSentPacketHandlerWithStats(utils.NewRTTStats(), &connStats)
			sph.SetCongestionControl(func(congestion.ByteCount) congestion.CongestionControl { return tc.cc }, 1200)
			now := monotime.Now()
			pns := send1RTTPackets(sph, now, 5)
			_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, now.Add(10*time.Millisecond))
			require.NoError(t, err)
			require.Equal(t, uint64(2), connStats.PacketsLost.Load())
			require.Equal(t, uint64(2400), connStats.BytesLost.Load())
		})
	}
}

// A lost path MTU probe says nothing about congestion. The built-in sender is
// not told about it (OnCongestionEvent), and a supplied controller must not see
// it in OnCongestionEventEx either. The probe's bytes leave the prior bytes in
// flight passed with that event, so that priorInFlight minus the acknowledged
// and lost bytes stays the bytes in flight after the event.
func TestSentPacketHandlerSuppliedCongestionControlIgnoresLostMTUProbes(t *testing.T) {
	const probeSize = 1400
	sendPacket := func(sph SentPacketHandler, now monotime.Time, isMTUProbe bool) protocol.PacketNumber {
		var packets packetTracker
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		size := protocol.ByteCount(1200)
		if isMTUProbe {
			size = probeSize
		}
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, size, isMTUProbe, false)
		return pn
	}

	t.Run("packet and time threshold", func(t *testing.T) {
		sph := newSentPacketHandlerForCongestionControlTest(utils.NewRTTStats())
		cc := &exCC{}
		sph.SetCongestionControl(func(congestion.ByteCount) congestion.CongestionControl { return cc }, 1200)

		now := monotime.Now()
		var pns []protocol.PacketNumber
		for i := range 5 {
			pns = append(pns, sendPacket(sph, now, i == 0 || i == 3))
		}

		// Acknowledging packet 4 declares packets 0 (the probe) and 1 lost.
		ackTime := now.Add(10 * time.Millisecond)
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[4])}, protocol.Encryption1RTT, ackTime)
		require.NoError(t, err)
		require.Equal(t, []congestion.PacketNumber{congestion.PacketNumber(pns[1])}, cc.lost)
		require.Equal(t, []congestionEvent{{
			priorInFlight: 3*1200 + probeSize,
			acked:         []congestion.AckedPacketInfo{{PacketNumber: congestion.PacketNumber(pns[4]), BytesAcked: 1200, ReceivedTime: ackTime}},
			lost:          []congestion.LostPacketInfo{{PacketNumber: congestion.PacketNumber(pns[1]), BytesLost: 1200}},
		}}, cc.events)

		// The loss timer declares packets 2 and 3 (the probe) lost.
		require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
		require.Equal(t, []congestion.PacketNumber{congestion.PacketNumber(pns[1]), congestion.PacketNumber(pns[2])}, cc.lost)
		require.Len(t, cc.events, 2)
		require.Equal(t, congestionEvent{
			priorInFlight: 1200,
			lost:          []congestion.LostPacketInfo{{PacketNumber: congestion.PacketNumber(pns[2]), BytesLost: 1200}},
		}, cc.events[1])
	})

	t.Run("only the probe is lost", func(t *testing.T) {
		sph := newSentPacketHandlerForCongestionControlTest(utils.NewRTTStats())
		cc := &exCC{}
		sph.SetCongestionControl(func(congestion.ByteCount) congestion.CongestionControl { return cc }, 1200)

		// The probe is sent first, so its loss deadline comes first.
		now := monotime.Now()
		sendPacket(sph, now, true)
		sendPacket(sph, now.Add(time.Millisecond), false)
		pn := sendPacket(sph, now.Add(time.Millisecond), false)
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.Encryption1RTT, now.Add(21*time.Millisecond))
		require.NoError(t, err)
		require.Len(t, cc.events, 1)
		require.Empty(t, cc.events[0].lost)

		// The loss timer declares only the probe lost: no congestion event.
		require.NoError(t, sph.OnLossDetectionTimeout(sph.GetLossDetectionTimeout()))
		require.Empty(t, cc.lost)
		require.Len(t, cc.events, 1)
		require.Equal(t, protocol.ByteCount(1200), sph.(*sentPacketHandler).bytesInFlight)
	})
}

// A PTO does not mean that a packet was lost (RFC 9002, section 6.2.4): the
// packets whose frames QueueProbePacket sends again stay in flight. A supplied
// controller has to learn each one's end like any other packet's: acknowledged
// when an ACK for it arrives, lost when loss detection declares it lost.
func TestSentPacketHandlerSuppliedCongestionControlAfterPTO(t *testing.T) {
	setup := func(t *testing.T) (*sentPacketHandler, *exCC, []protocol.PacketNumber, monotime.Time) {
		t.Helper()
		sph := newSentPacketHandlerForCongestionControlTest(utils.NewRTTStats()).(*sentPacketHandler)
		cc := &exCC{}
		sph.SetCongestionControl(func(congestion.ByteCount) congestion.CongestionControl { return cc }, 1200)
		now := monotime.Now()
		sph.DropPackets(protocol.EncryptionInitial, now)
		sph.DropPackets(protocol.EncryptionHandshake, now)
		pns := send1RTTPackets(sph, now, 3)

		timeout := sph.GetLossDetectionTimeout()
		require.False(t, timeout.IsZero())
		require.NoError(t, sph.OnLossDetectionTimeout(timeout))
		require.Equal(t, SendPTOAppData, sph.SendMode(timeout))
		require.True(t, sph.QueueProbePacket(protocol.Encryption1RTT))
		require.True(t, sph.QueueProbePacket(protocol.Encryption1RTT))
		// the PTO itself reports nothing and takes nothing out of flight
		require.Empty(t, cc.lost)
		require.Empty(t, cc.events)
		require.Equal(t, protocol.ByteCount(3*1200), sph.bytesInFlight)
		return sph, cc, pns, timeout
	}

	t.Run("acknowledged after the probe", func(t *testing.T) {
		sph, cc, pns, timeout := setup(t)
		ackTime := timeout.Add(time.Millisecond)
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2])}, protocol.Encryption1RTT, ackTime)
		require.NoError(t, err)
		require.Equal(t, []congestion.PacketNumber{congestion.PacketNumber(pns[0]), congestion.PacketNumber(pns[1]), congestion.PacketNumber(pns[2])}, cc.acked)
		require.Empty(t, cc.lost)
		require.Equal(t, []congestionEvent{{
			priorInFlight: 3 * 1200,
			acked: []congestion.AckedPacketInfo{
				{PacketNumber: congestion.PacketNumber(pns[0]), BytesAcked: 1200, ReceivedTime: ackTime},
				{PacketNumber: congestion.PacketNumber(pns[1]), BytesAcked: 1200, ReceivedTime: ackTime},
				{PacketNumber: congestion.PacketNumber(pns[2]), BytesAcked: 1200, ReceivedTime: ackTime},
			},
		}}, cc.events)
		require.Zero(t, sph.bytesInFlight)
	})

	t.Run("declared lost after the probe", func(t *testing.T) {
		sph, cc, pns, timeout := setup(t)
		// Three probe packets later, an ACK for the last of them declares the
		// first three packets lost by the packet threshold.
		probes := send1RTTPackets(sph, timeout, 3)
		ackTime := timeout.Add(time.Millisecond)
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(probes...)}, protocol.Encryption1RTT, ackTime)
		require.NoError(t, err)
		require.Equal(t, []congestion.PacketNumber{congestion.PacketNumber(pns[0]), congestion.PacketNumber(pns[1]), congestion.PacketNumber(pns[2])}, cc.lost)
		require.Len(t, cc.events, 1)
		require.Equal(t, []congestion.LostPacketInfo{
			{PacketNumber: congestion.PacketNumber(pns[0]), BytesLost: 1200},
			{PacketNumber: congestion.PacketNumber(pns[1]), BytesLost: 1200},
			{PacketNumber: congestion.PacketNumber(pns[2]), BytesLost: 1200},
		}, cc.events[0].lost)
		require.Zero(t, sph.bytesInFlight)
	})
}
