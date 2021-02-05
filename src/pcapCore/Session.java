package pcapCore;

import java.util.ArrayList;
import java.util.List;

import protocols.LayerProtocol;

public class Session {

	private List<PcapPacket> packets = new ArrayList<PcapPacket>();
	private int id;

	public Session(int id) {
		this.id = id;
	}

	public List<PcapPacket> getPackets() {
		return packets;
	}

	public int getId() {
		return id;
	}

	public void addPacket(PcapPacket packet) {
		packets.add(packet);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Session: ");
		if (packets.size() > 0) {
			String srcIP = "?";
			String srcPort = "?";
			String dstIP = "?";
			String dstPort = "?";

			for (LayerProtocol proto : packets.get(0).getProtocolStack()) {
				if (proto.getOsiLayer() == 3) {
					srcIP = proto.getSrcAddress();
					dstIP = proto.getDstAddress();
				} else if (proto.getOsiLayer() == 4) {
					srcPort = proto.getSrcAddress();
					dstPort = proto.getDstAddress();
				}
			}
			sb.append(srcIP);
			sb.append(":");
			sb.append(srcPort);
			sb.append(" <-> ");
			sb.append(dstIP);
			sb.append(":");
			sb.append(dstPort);
			sb.append(" , stack: ");
			sb.append(packets.get(0).printProtocolStack());
			sb.append(" , ");
		}
		sb.append("packtes: ");
		sb.append(packets.size());
		return sb.toString();
	}

}
