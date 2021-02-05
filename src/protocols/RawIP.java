package protocols;

import java.nio.ByteBuffer;

import pcapCore.PcapHeader;

public class RawIP extends LayerProtocol {

	@Override
	public LayerProtocol parseLayer(ByteBuffer buffer, PcapHeader pcapHeader) {
		name = "RawIP";
		osiLayer = 2;
		int version = (buffer.get() & 0x00ff) >>> 4;
		buffer.position(buffer.position() - 1);
		switch (version) {
		case 4:
			nextLayerProtocol = new IPv4Protocol();
			break;
		case 6:
			nextLayerProtocol = new IPv6Protocol();
			break;
		default:
			System.out.println("invalid ip version nibble: " + version);
			nextLayerProtocol = null;
			break;
		}
		return nextLayerProtocol;
	}

	@Override
	public String toString() {
		return "RawIP";
	}

	@Override
	public String getSrcAddress() {
		return nextLayerProtocol.getSrcAddress();
	}

	@Override
	public String getDstAddress() {
		return nextLayerProtocol.getDstAddress();
	}

}
