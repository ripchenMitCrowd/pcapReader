package protocols;

import java.nio.ByteBuffer;

import pcapCore.PcapHeader;

public class IPv4Protocol extends LayerProtocol {

	private String srcIP;
	private String dstIP;

	@Override
	public String getSrcAddress() {
		return srcIP;
	}

	@Override
	public String getDstAddress() {
		return dstIP;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(name);
		sb.append(": ");
		sb.append(srcIP);
		sb.append(" -> ");
		sb.append(dstIP);
		return sb.toString();
	}

	@Override
	public LayerProtocol parseLayer(ByteBuffer buffer, PcapHeader pcapHeader) {
		name = "IPv4";
		osiLayer = 3;
		byte version = buffer.get();
		int extHeaderLen = 4 * (version & 0x0f) - 20;
		buffer.position(buffer.position() + 8);
		byte nextProto = buffer.get();
		buffer.position(buffer.position() + 2);
		srcIP = parseIP(buffer);
		dstIP = parseIP(buffer);
		if (extHeaderLen > 0) {
			buffer.position(buffer.position() + extHeaderLen);
		}
		setNextLayerProtocol(nextProto);
		return nextLayerProtocol;
	}

	private String parseIP(ByteBuffer buffer) {
		StringBuilder sb = new StringBuilder();
		sb.append(buffer.get() & 0xff);
		sb.append(".");
		sb.append(buffer.get() & 0xff);
		sb.append(".");
		sb.append(buffer.get() & 0xff);
		sb.append(".");
		sb.append(buffer.get() & 0xff);
		return sb.toString();
	}
}
