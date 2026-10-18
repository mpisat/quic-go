package quic

import (
	"context"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestBidirectionalStreamAtomicFinalData(t *testing.T) {
	const id protocol.StreamID = 42
	sender := NewMockStreamSender(gomock.NewController(t))
	s := newStream(context.Background(), id, sender, newTestStreamFlowControllerWithSendWindow(id, protocol.MaxByteCount), false)
	atomic, ok := any(s).(interface{ TryWriteAllAndClose([]byte) error })
	require.True(t, ok, "bidirectional streams must expose the atomic send operation")
	sender.EXPECT().onHasStreamData(id, gomock.Any()).Do(func(protocol.StreamID, *SendStream) {
		f, _, more := s.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
		require.Equal(t, []byte("final"), f.Frame.Data)
		require.True(t, f.Frame.Fin)
		require.False(t, more)
	})
	require.NoError(t, atomic.TryWriteAllAndClose([]byte("final")))
}
