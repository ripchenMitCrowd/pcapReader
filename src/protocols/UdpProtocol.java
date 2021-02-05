package protocols;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import pcapCore.PcapHeader;

public class UdpProtocol extends LayerProtocol {

	private String srcPort;
	private String dstPort;

	@Override
	public String getSrcAddress() {
		return srcPort;
	}

	@Override
	public String getDstAddress() {
		return dstPort;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(name);
		sb.append(": ");
		sb.append(srcPort);
		sb.append(" -> ");
		sb.append(dstPort);
		return sb.toString();
	}

	@Override
	public LayerProtocol parseLayer(ByteBuffer buffer, PcapHeader pcapHeader) {
		name = "UDP";
		osiLayer = 4;
		buffer.order(ByteOrder.BIG_ENDIAN);
		srcPort = String.valueOf(buffer.getShort() & 0xffff);
		dstPort = String.valueOf(buffer.getShort() & 0xffff);
		// int payloadLen = (buffer.getShort() & 0xffff) - 8;
		buffer.position(buffer.position() + 4);
		if (buffer.hasRemaining()) {
			nextLayerProtocol = new ApplicationLayerProtocol();
		} else {
			nextLayerProtocol = null;
		}
		return nextLayerProtocol;
	}

}
