package self_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/congestion"
	"github.com/quic-go/quic-go/monotime"

	"github.com/stretchr/testify/require"
)

// fixedWindowCC is a congestion controller with a constant window and no pacing.
type fixedWindowCC struct {
	window                congestion.ByteCount
	sent, acked, exEvents *atomic.Int64
}

func (c *fixedWindowCC) SetRTTStatsProvider(congestion.RTTStatsProvider)  {}
func (c *fixedWindowCC) TimeUntilSend(congestion.ByteCount) monotime.Time { return 0 }
func (c *fixedWindowCC) HasPacingBudget(monotime.Time) bool               { return true }
func (c *fixedWindowCC) CanSend(inFlight congestion.ByteCount) bool       { return inFlight < c.window }
func (c *fixedWindowCC) MaybeExitSlowStart()                              {}
func (c *fixedWindowCC) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}
func (c *fixedWindowCC) OnRetransmissionTimeout(bool)              {}
func (c *fixedWindowCC) SetMaxDatagramSize(congestion.ByteCount)   {}
func (c *fixedWindowCC) InSlowStart() bool                         { return false }
func (c *fixedWindowCC) InRecovery() bool                          { return false }
func (c *fixedWindowCC) GetCongestionWindow() congestion.ByteCount { return c.window }

func (c *fixedWindowCC) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
	c.sent.Add(1)
}

func (c *fixedWindowCC) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
	c.acked.Add(1)
}

func (c *fixedWindowCC) OnCongestionEventEx(congestion.ByteCount, monotime.Time, []congestion.AckedPacketInfo, []congestion.LostPacketInfo) {
	c.exEvents.Add(1)
}

func TestSuppliedCongestionControl(t *testing.T) {
	var made, sent, acked, exEvents atomic.Int64
	var initialPacketSize atomic.Int64
	serverConf := getQuicConfig(&quic.Config{
		InitialPacketSize: 1300,
		CongestionControl: func(size congestion.ByteCount) congestion.CongestionControl {
			made.Add(1)
			initialPacketSize.Store(int64(size))
			return &fixedWindowCC{window: 20 * size, sent: &sent, acked: &acked, exEvents: &exEvents}
		},
	})
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), serverConf)
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		str, err := conn.OpenUniStream()
		if err != nil {
			return
		}
		str.Write(PRData)
		str.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	str, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)

	require.Equal(t, int64(1), made.Load())
	require.Equal(t, int64(1300), initialPacketSize.Load())
	// PRData does not fit into fewer packets than this
	minPackets := int64(len(PRData) / 1452)
	require.GreaterOrEqual(t, sent.Load(), minPackets)
	require.Eventually(t, func() bool { return acked.Load() >= minPackets }, time.Second, 10*time.Millisecond)
	require.Positive(t, exEvents.Load())
}
