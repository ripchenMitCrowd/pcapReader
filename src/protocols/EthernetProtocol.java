package protocols;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import pcapCore.PcapHeader;

public class EthernetProtocol extends LayerProtocol {

	private String srcMac;
	private String dstMac;

	private String parseMac(ByteBuffer buffer) {
		byte[] mac = new byte[6];
		buffer.get(mac);
		return String.format("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	@Override
	public String getSrcAddress() {
		return srcMac;
	}

	@Override
	public String getDstAddress() {
		return dstMac;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Ethernet: ");
		sb.append(srcMac);
		sb.append(" -> ");
		sb.append(dstMac);
		return sb.toString();
	}

	@Override
	public LayerProtocol parseLayer(ByteBuffer buffer, PcapHeader pcapHeader) {
		name = "Ethernet";
		osiLayer = 2;
		dstMac = parseMac(buffer);
		srcMac = parseMac(buffer);

		buffer.order(ByteOrder.BIG_ENDIAN);
		int nextProto = buffer.getShort();
		buffer.order(pcapHeader.getOrder());
		setNextLayerProtocol(nextProto);
		return nextLayerProtocol;
	}

}
