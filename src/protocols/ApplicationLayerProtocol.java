package protocols;

import java.nio.ByteBuffer;

import pcapCore.PcapHeader;

public class ApplicationLayerProtocol extends LayerProtocol {

	private byte[] payload;

	@Override
	public String getSrcAddress() {
		return null;
	}

	@Override
	public String getDstAddress() {
		return null;
	}

	@Override
	public LayerProtocol parseLayer(ByteBuffer buffer, PcapHeader pcapHeader) {
		name = "Application";
		osiLayer = 5;
		int len = buffer.remaining();
		if (pcapHeader.isNg()) {
			len -= 4;
		}
		payload = new byte[len];
		buffer.get(payload);
		return null;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(name);
		sb.append(" , payload size: ");
		sb.append(payload.length);
		sb.append("\n");
		for (byte b : payload) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}

	public byte[] getPayload() {
		return payload;
	}

}
