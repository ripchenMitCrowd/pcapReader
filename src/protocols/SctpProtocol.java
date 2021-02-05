package protocols;

import java.nio.ByteBuffer;

import pcapCore.PcapHeader;

public class SctpProtocol extends LayerProtocol {

	private String srcPort;
	private String dstPort;

	@Override
	public LayerProtocol parseLayer(ByteBuffer buffer, PcapHeader pcapHeader) {
		// TODO Auto-generated method stub
		return null;
	}

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

}
