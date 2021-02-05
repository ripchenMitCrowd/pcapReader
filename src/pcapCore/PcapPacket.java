package pcapCore;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.ArrayList;
import java.util.List;

import protocols.EthernetProtocol;
import protocols.IPv4Protocol;
import protocols.IPv6Protocol;
import protocols.LayerProtocol;
import protocols.RawIP;

public class PcapPacket extends ChannelReader {

	private PacketHeader header;
	private byte[] payload;
	private List<LayerProtocol> protocolStack;
	private int id;

	public static PcapPacket readNextPacket(ReadableByteChannel channel, PcapHeader pcapHeader) throws IOException {
		PacketHeader header = new PacketHeader(channel, pcapHeader);
		if (!header.isValid()) {
			return null;
		}

		PcapPacket packet = new PcapPacket(header, channel, pcapHeader);
		if (!header.isValid()) {
			packet = null;
		}
		return packet;
	}

	public PcapPacket(PacketHeader packetHeader, ReadableByteChannel channel, PcapHeader pcapHeader)
			throws IOException {
		header = packetHeader;
		ByteBuffer buffer;
		if (header.getCapturedLength() == 0) {
			return;
		}
		if (pcapHeader.isNg()) {
			buffer = header.getBuffer();
		} else {
			buffer = readToBuffer(channel, header.getCapturedLength(), pcapHeader.getOrder());
		}
		if (buffer == null || buffer.array().length < 4) {
			header.setCapturedLength(-1);
			return;
		}
		payload = buffer.array();

		LayerProtocol nextLayerProto = null;
		switch (pcapHeader.getLinkType()) {
		case 1: // ETHERNET
			nextLayerProto = new EthernetProtocol();
			break;
		case 6: // IEEE802_5
			// TODO
			// nextLayerProto = new
			break;
		case 9: // PPP
			// TODO
			// nextLayerProto = new
			break;
		case 50: // PPP_HDLC
			// TODO
			// nextLayerProto = new
			break;
		case 51: // PPP_ETHER
			// TODO
			// nextLayerProto = new
			break;
		case 101: // RAW_IP 4/6
			nextLayerProto = new RawIP();
			break;
		case 104: // C_HDLC
			// TODO
			// nextLayerProto = new
			break;
		case 105: // IEEE802_11
			// TODO
			// nextLayerProto = new
			break;
		case 107: // Frame Relay LAPF
			// TODO
			// nextLayerProto = new
			break;
		case 122: // IP_OVER_FC
			// TODO
			// nextLayerProto = new
			break;
		case 228: // IPV4
			nextLayerProto = new IPv4Protocol();
			break;
		case 229: // IPV6
			nextLayerProto = new IPv6Protocol();
			break;
		// TODO
//		case : // MPLS 
//			nextLayerProto = new MplsProtocol();
//			break;
		default:
			System.out.println(
					"unkown network value in pcap header: " + pcapHeader.getLinkType() + " cannot parse first layer");
			return;
		}

		protocolStack = new ArrayList<>();
		while (nextLayerProto != null) {
			protocolStack.add(nextLayerProto);
			nextLayerProto = nextLayerProto.parseLayer(buffer, pcapHeader);
		}
		generateID();
	}

	@Override
	public String toString() {
		if (header.getCapturedLength() == 0) {
			return "pcap NG block";
		}
		StringBuilder sb = new StringBuilder();
		sb.append("--- PcapPacket ---\n");
		sb.append(header.toString());
		sb.append("\nProtocol Stack: ");
		sb.append(printProtocolStack());
		sb.append('\n');
		for (int i = 0; i < protocolStack.size(); ++i) {
			LayerProtocol proto = protocolStack.get(i);
			sb.append(proto.toString());
			if (i < protocolStack.size() - 1) {
				sb.append('\n');
			}
		}
		return sb.toString();
	}

	public String printProtocolStack() {
		if (protocolStack == null || protocolStack.size() == 0) {
			return "no";
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < protocolStack.size(); ++i) {
			LayerProtocol proto = protocolStack.get(i);
			sb.append(proto.getName());
			if (i < protocolStack.size() - 1) {
				sb.append(":");
			}
		}
		return sb.toString();
	}

	public PacketHeader getHeader() {
		return header;
	}

	public boolean isValid() {
		return header.isValid();
	}

	public byte[] getPayload() {
		return payload;
	}

	public List<LayerProtocol> getProtocolStack() {
		return protocolStack;
	}

	private void generateID() {
		String srcIpPort = "?";
		String dstIpPort = "?";

		for (LayerProtocol proto : protocolStack) {
			if (proto.getOsiLayer() == 3) {
				srcIpPort = proto.getSrcAddress() + proto.getNextLayerProtocol().getName();
				dstIpPort = proto.getDstAddress() + proto.getNextLayerProtocol().getName();
			} else if (proto.getOsiLayer() == 4) {
				srcIpPort += proto.getSrcAddress();
				dstIpPort += proto.getDstAddress();
			}
		}
		id = srcIpPort.hashCode() + dstIpPort.hashCode();
	}

	@Override
	public int hashCode() {
		return id;
	}

	public boolean isPcapNgBlock() {
		return header.getCapturedLength() == 0;
	}

}
