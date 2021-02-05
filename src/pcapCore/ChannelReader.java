package pcapCore;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;

public abstract class ChannelReader {

	protected ByteBuffer readToBuffer(ReadableByteChannel channel, int len, ByteOrder order) throws IOException {
		ByteBuffer buffer = ByteBuffer.allocate(len);
		buffer.order(order);
		while (buffer.hasRemaining()) {
			if (channel.read(buffer) < 0) {
				order = null;
				return null;
			}
		}
		buffer.flip();
		return buffer;
	}
}
