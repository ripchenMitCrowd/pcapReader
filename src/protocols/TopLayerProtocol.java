package protocols;

import java.nio.ByteBuffer;

import pcapCore.PcapHeader;

public class TopLayerProtocol extends LayerProtocol {

	public TopLayerProtocol(String name, int osiLayer) {
		this.name = name;
		this.osiLayer = osiLayer;
	}

	@Override
	public LayerProtocol parseLayer(ByteBuffer buffer, PcapHeader pcapHeader) {
		return null;
	}

	@Override
	public String getSrcAddress() {
		return null;
	}

	@Override
	public String getDstAddress() {
		return null;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(name);
		sb.append(" (layer ");
		sb.append(osiLayer);
		sb.append(")");
		return name;
	}

}
