package quic

import (
	"context"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestSafariAtomicPacketizerInterleaving(t *testing.T) {
	const id protocol.StreamID = 42
	sender := NewMockStreamSender(gomock.NewController(t))
	s := newSendStream(context.Background(), id, sender, newTestStreamFlowControllerWithSendWindow(id, protocol.MaxByteCount), false)
	sender.EXPECT().onHasStreamData(id, s).Do(func(protocol.StreamID, *SendStream) {
		f, _, more := s.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
		require.Equal(t, []byte("foobar"), f.Frame.Data)
		require.True(t, f.Frame.Fin, "packetizer must observe FIN with final data")
		require.False(t, more)
	})
	require.NoError(t, s.TryWriteAllAndClose([]byte("foobar")))
}

func TestSafariAtomicSplitFrames(t *testing.T) {
	const id protocol.StreamID = 42
	sender := NewMockStreamSender(gomock.NewController(t))
	s := newSendStream(context.Background(), id, sender, newTestStreamFlowControllerWithSendWindow(id, protocol.MaxByteCount), false)
	data := make([]byte, 12000)
	sender.EXPECT().onHasStreamData(id, s)
	require.NoError(t, s.TryWriteAllAndClose(data))
	for offset := 0; offset < len(data); {
		f, _, more := s.popStreamFrame(expectedFrameHeaderLen(id, protocol.ByteCount(offset))+40, protocol.Version1)
		require.NotNil(t, f.Frame)
		require.Equal(t, protocol.ByteCount(offset), f.Frame.Offset)
		require.Len(t, f.Frame.Data, 40)
		offset += len(f.Frame.Data)
		require.Equal(t, offset == len(data), f.Frame.Fin)
		require.Equal(t, offset < len(data), more)
	}
	f, _, more := s.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, f.Frame)
	require.False(t, more)
}

func TestSafariAtomicCancelReset(t *testing.T) {
	const id protocol.StreamID = 42
	sender := NewMockStreamSender(gomock.NewController(t))
	s := newSendStream(context.Background(), id, sender, newTestStreamFlowControllerWithSendWindow(id, 100), false)
	sender.EXPECT().onHasStreamData(id, s)
	require.NoError(t, s.TryWriteAllAndClose(make([]byte, 100)))
	f, _, more := s.popStreamFrame(expectedFrameHeaderLen(id, 0)+40, protocol.Version1)
	require.True(t, more)
	require.False(t, f.Frame.Fin)
	sender.EXPECT().onHasStreamControlFrame(id, s)
	s.CancelWrite(42)
	cf, ok, _ := s.getControlFrame(monotime.Now())
	require.True(t, ok)
	require.Equal(t, &wire.ResetStreamFrame{StreamID: id, FinalSize: 100, ErrorCode: 42}, cf.Frame)
	require.ErrorIs(t, s.TryWriteAllAndClose([]byte("x")), &StreamError{StreamID: id, ErrorCode: 42, Remote: false})
}
