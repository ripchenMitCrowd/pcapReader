package protocols;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import pcapCore.PcapHeader;

public class TcpProtocol extends LayerProtocol {

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
		name = "TCP";
		osiLayer = 4;
		buffer.order(ByteOrder.BIG_ENDIAN);
		srcPort = String.valueOf(buffer.getShort() & 0xffff);
		dstPort = String.valueOf(buffer.getShort() & 0xffff);
		buffer.position(buffer.position() + 8);
		int remainingHeaderLen = (4 * ((buffer.get() & 0x00ff) >>> 4)) - 13;
		buffer.position(buffer.position() + remainingHeaderLen);
		if (buffer.hasRemaining()) {
			nextLayerProtocol = new ApplicationLayerProtocol();
		} else {
			nextLayerProtocol = null;
		}
		return nextLayerProtocol;
	}
}
