package protocols;

import java.nio.ByteBuffer;

import pcapCore.PcapHeader;

public class IPv6Protocol extends LayerProtocol {

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
		name = "IPv6";
		osiLayer = 3;
		buffer.position(buffer.position() + 6);
		int nextProtoByte = buffer.get();
		buffer.position(buffer.position() + 1);
		srcIP = parseIP(buffer);
		dstIP = parseIP(buffer);
		setNextLayerProtocol(nextProtoByte);
		return nextLayerProtocol;
	}

	private String parseIP(ByteBuffer buffer) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 16; ++i) {
			sb.append(String.format("%02X", buffer.get()));
			if (i < 15 && i % 2 != 0) {
				sb.append(":");
			}
		}
		return sb.toString();
	}
}
