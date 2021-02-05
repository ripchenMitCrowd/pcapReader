package pcapCore;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;

public class PcapHeader extends ChannelReader {

	private static final int magicLittle = 0xD4C3B2A1;
	private static final int magicBig = 0xA1B2C3D4;
	private static final int magicNg = 0x0A0D0D0A;
	private static final int orderMagicNg = 0x1A2B3C4D;
	private static final int magicNgLittle = 0x4D3C2B1A;
	private int magicNumber;
	private int versionMajor;
	private int versionMinor;
	private int thisZone;
	private int sigFigs;
	private long snapLen;
	private int linkType;
	private ByteOrder order;
	private boolean ng = false;

	public PcapHeader(ReadableByteChannel channel) throws IOException {
		ByteBuffer buffer = readToBuffer(channel, 4, ByteOrder.BIG_ENDIAN);
		if (buffer == null) {
			order = null;
			return;
		}

		magicNumber = buffer.getInt();
		order = buffer.order();
		if (magicNumber == magicLittle) {
			order = ByteOrder.LITTLE_ENDIAN;
			readNormalPcapHeader(channel);
		} else if (magicNumber == magicBig) {
			order = ByteOrder.BIG_ENDIAN;
			readNormalPcapHeader(channel);
		} else if (magicNumber == magicNg) {
			readPcapNgHeader(channel);
		} else {
			order = null;
			return;
		}
	}

	private void readNormalPcapHeader(ReadableByteChannel channel) throws IOException {
		ByteBuffer buffer = readToBuffer(channel, 20, order);
		if (buffer == null) {
			order = null;
			return;
		}
		versionMajor = buffer.getShort();
		versionMinor = buffer.getShort();
		thisZone = buffer.getInt();
		sigFigs = buffer.getInt();
		snapLen = buffer.getInt();
		linkType = buffer.getInt();
	}

	private void readPcapNgHeader(ReadableByteChannel channel) throws IOException {
		ByteBuffer buffer = readToBuffer(channel, 12, ByteOrder.BIG_ENDIAN);
		if (buffer == null) {
			order = null;
			return;
		}
		int blockTotalLength = buffer.getInt();
		int orderMagic = buffer.getInt();
		if (orderMagic == magicNgLittle) {
			order = ByteOrder.LITTLE_ENDIAN;
			buffer.order(order);
			buffer.rewind();
		} else {
			order = ByteOrder.BIG_ENDIAN;
		}
		blockTotalLength = buffer.getInt();
		orderMagic = buffer.getInt();
		if (orderMagic != orderMagicNg) {
			order = null;
			return;
		}
		versionMajor = buffer.getShort();
		versionMinor = buffer.getShort();

		buffer = readToBuffer(channel, blockTotalLength - 16, order);
		if (buffer == null) {
			System.out.println("failed to read pcapng header");
			order = null;
			return;
		}
		ng = true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("--- PcapHeader ---");
		sb.append("\nNG:");
		sb.append(ng);
		sb.append("\nmagicNumber: ");
		sb.append(magicNumber);
		sb.append("\nversion: ");
		sb.append(versionMajor);
		sb.append(".");
		sb.append(versionMinor);
		sb.append("\nlinkType: ");
		sb.append(linkType);
		return sb.toString();
	}

	public int getMagicNumber() {
		return magicNumber;
	}

	public int getVersionMajor() {
		return versionMajor;
	}

	public int getVersionMinor() {
		return versionMinor;
	}

	public int getThisZone() {
		return thisZone;
	}

	public int getSigFigs() {
		return sigFigs;
	}

	public long getSnapLen() {
		return snapLen;
	}

	public int getLinkType() {
		return linkType;
	}

	public ByteOrder getOrder() {
		return order;
	}

	public boolean isValid() {
		return order != null;
	}

	public boolean isNg() {
		return ng;
	}

	public void setLinkType(int linkType) {
		this.linkType = linkType;
	}

	public void setSnapLen(long snapLen) {
		this.snapLen = snapLen;
	}

}
