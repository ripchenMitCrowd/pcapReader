package pcapCore;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class PacketHeader extends ChannelReader {

	private long timeStampSec;
	private int timeStampMicrosec;
	private int capturedLength = -1;
	private int origLen;
	private ByteBuffer buffer;

	public PacketHeader(ReadableByteChannel channel, PcapHeader pcapHeader) throws IOException {
		if (pcapHeader.isNg()) {
			ByteBuffer buffer = readToBuffer(channel, 8, pcapHeader.getOrder());
			if (buffer == null) {
				return;
			}
			int blockType = buffer.getInt();
			int blockLength = buffer.getInt();
			buffer = readToBuffer(channel, blockLength - 8, pcapHeader.getOrder());

			switch (blockType) {
			case 1: // Interface Description Block
				capturedLength = 0;
				pcapHeader.setLinkType(buffer.getShort());
				buffer.position(buffer.position() + 2);
				pcapHeader.setSnapLen(buffer.getInt());
				// additional options are skipped
				break;
			case 3: {// Simple Packet Block
				capturedLength = buffer.getInt();
				origLen = capturedLength;
				long ts = System.currentTimeMillis();
				timeStampMicrosec = (int) (ts % 1000L);
				timeStampSec = (ts - timeStampMicrosec) / 1000L;
				this.buffer = buffer;
			}
				break;
			case 6: {// Enhanced Packet Block
				buffer.position(buffer.position() + 4);
				long timeHigh = buffer.getInt();
				long timeLow = buffer.getInt();
				long ts = timeHigh << 32 | timeLow;
				timeStampMicrosec = (int) (ts % 1000000L);
				timeStampSec = (ts - timeStampMicrosec) / 1000000L;
				capturedLength = buffer.getInt();
				origLen = buffer.getInt();
				this.buffer = buffer;
				// additional options are skipped
			}
				break;
			case 4: // Name Resolution Block
				capturedLength = 0;
				System.out.println("skip Name Resolution Block");
				break;
			case 5: // Interface Statistics Block
				capturedLength = 0;
				System.out.println("skip Interface Statistics Block");
				break;
			case 9: // systemd Journal Export Block
				capturedLength = 0;
				System.out.println("skip systemd Journal Export Block");
				break;
			case 10: // Decryption Secrets Block
				capturedLength = 0;
				System.out.println("skip Decryption Secrets Block");
				break;
			case 2989: // custom Block
			case 1073744813:// custom Block
				capturedLength = 0;
				System.out.println("skip custom Block");
				break;
			default:
				capturedLength = 0;
				System.out.println("skip unknown block of type: " + blockType);
				break;
			}
		} else {
			ByteBuffer buffer = readToBuffer(channel, 16, pcapHeader.getOrder());
			if (buffer == null) {
				return;
			}
			timeStampSec = buffer.getInt();
			timeStampMicrosec = buffer.getInt();
			capturedLength = buffer.getInt();
			origLen = buffer.getInt();
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("time: ");
		sb.append(timeStampSec);
		sb.append(" -> ");
		sb.append(LocalDateTime.ofEpochSecond((int) timeStampSec, 1000 * timeStampMicrosec, ZoneOffset.UTC).toString());
		sb.append("\npacket Length: ");
		sb.append(capturedLength);
		sb.append(" bytes , original Length: ");
		sb.append(origLen);
		sb.append(" bytes");
		return sb.toString();
	}

	public boolean isValid() {
		return (capturedLength >= 0);
	}

	public long getTimeStampSec() {
		return timeStampSec;
	}

	public int getTimeStampMicrosec() {
		return timeStampMicrosec;
	}

	public int getCapturedLength() {
		return capturedLength;
	}

	public int getOrigLen() {
		return origLen;
	}

	public ByteBuffer getBuffer() {
		return buffer;
	}

	public void setCapturedLength(int capturedLength) {
		this.capturedLength = capturedLength;
	}

}
