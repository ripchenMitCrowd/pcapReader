package protocols;

import java.nio.ByteBuffer;

import pcapCore.PcapHeader;

public abstract class LayerProtocol {

	protected String name;
	protected int osiLayer;
	protected LayerProtocol nextLayerProtocol;

	public abstract LayerProtocol parseLayer(ByteBuffer buffer, PcapHeader pcapHeader);

	public abstract String getSrcAddress();

	public abstract String getDstAddress();

	@Override
	abstract public String toString();

	public String getName() {
		return name;
	}

	public int getOsiLayer() {
		return osiLayer;
	}

	public LayerProtocol getNextLayerProtocol() {
		return nextLayerProtocol;
	}

	protected void setNextLayerProtocol(int nextProto) {
		switch (nextProto) {
		case 6:
			nextLayerProtocol = new TcpProtocol();
			break;
		case 17:
			nextLayerProtocol = new UdpProtocol();
			break;
		case 4: // IPv4
		case 2048:
			nextLayerProtocol = new IPv4Protocol();
			break;
		case -31011:
			nextLayerProtocol = new IPv6Protocol();
			break;
		case 0:
			nextLayerProtocol = new TopLayerProtocol("HOPOPT", 3);
			break;
		case 1:
			nextLayerProtocol = new TopLayerProtocol("ICMP", 3);
			break;
		case 2:
			nextLayerProtocol = new TopLayerProtocol("IGMP", 3);
			break;
		case 3:
			nextLayerProtocol = new TopLayerProtocol("GGP", 3);
			break;
		case 5:
			nextLayerProtocol = new TopLayerProtocol("Stream", 4);
			break;
		case 7:
			nextLayerProtocol = new TopLayerProtocol("CBT", 4);
			break;
		case 8:
			nextLayerProtocol = new TopLayerProtocol("EGP ", 4);
			break;
		case 9:
			nextLayerProtocol = new TopLayerProtocol("IGP", 4);
			break;
		case 10:
			nextLayerProtocol = new TopLayerProtocol("BBN-RCC-MON", 4);
			break;
		case 11:
			nextLayerProtocol = new TopLayerProtocol("NVP-II", 4);
			break;
		case 12:
			nextLayerProtocol = new TopLayerProtocol("PUP", 4);
			break;
		case 13:
			nextLayerProtocol = new TopLayerProtocol("ARGUS", 4);
			break;
		case 14:
			nextLayerProtocol = new TopLayerProtocol("EMCON", 4);
			break;
		case 15:
			nextLayerProtocol = new TopLayerProtocol("XNET", 4);
			break;
		case 16:
			nextLayerProtocol = new TopLayerProtocol("CHAOS", 4);
			break;
		case 18:
			nextLayerProtocol = new TopLayerProtocol("Multiplexing", 4);
			break;
		case 19:
			nextLayerProtocol = new TopLayerProtocol("DCN-MEAS", 4);
			break;
		case 20:
			nextLayerProtocol = new TopLayerProtocol("HMP", 4);
			break;
		case 21:
			nextLayerProtocol = new TopLayerProtocol("PRM", 4);
			break;
		case 22:
			nextLayerProtocol = new TopLayerProtocol("XNS-IDP", 4);
			break;
		case 23:
			nextLayerProtocol = new TopLayerProtocol("TRUNK-1", 4);
			break;
		case 24:
			nextLayerProtocol = new TopLayerProtocol("TRUNK-2", 4);
			break;
		case 25:
			nextLayerProtocol = new TopLayerProtocol("LEAF-1", 4);
			break;
		case 26:
			nextLayerProtocol = new TopLayerProtocol("LEAF-2", 4);
			break;
		case 27:
			nextLayerProtocol = new TopLayerProtocol("RDP", 4);
			break;
		case 28:
			nextLayerProtocol = new TopLayerProtocol("IRTP", 4);
			break;
		case 29:
			nextLayerProtocol = new TopLayerProtocol("ISO-TP4", 4);
			break;
		case 30:
			nextLayerProtocol = new TopLayerProtocol("NETBLT", 4);
			break;
		case 31:
			nextLayerProtocol = new TopLayerProtocol("MFE-NSP", 4);
			break;
		case 32:
			nextLayerProtocol = new TopLayerProtocol("MERIT-INP", 4);
			break;
		case 33:
			nextLayerProtocol = new TopLayerProtocol("DCCP", 4);
			break;
		case 34:
			nextLayerProtocol = new TopLayerProtocol("3PC", 4);
			break;
		case 35:
			nextLayerProtocol = new TopLayerProtocol("IDPR", 4);
			break;
		case 36:
			nextLayerProtocol = new TopLayerProtocol("XTP", 4);
			break;
		case 37:
			nextLayerProtocol = new TopLayerProtocol("DDP", 4);
			break;
		case 38:
			nextLayerProtocol = new TopLayerProtocol("IDPR-CMTP", 4);
			break;
		case 39:
			nextLayerProtocol = new TopLayerProtocol("TP++", 4);
			break;
		case 40:
			nextLayerProtocol = new TopLayerProtocol("IL", 4);
			break;
		case 41:
			nextLayerProtocol = new IPv6Protocol();
			break;
		case 42:
			nextLayerProtocol = new TopLayerProtocol("SDRP", 4);
			break;
		case 43:
			nextLayerProtocol = new TopLayerProtocol("IPv6-Route", 3);
			break;
		case 44:
			nextLayerProtocol = new TopLayerProtocol("IPv6-Frag", 3);
			break;
		case 45:
			nextLayerProtocol = new TopLayerProtocol("IDRP", 3);
			break;
		case 46:
			nextLayerProtocol = new TopLayerProtocol("RSVP", 4);
			break;
		case 47: // GRE
			// TODO nextLayerProtocol = new ;
			break;
		case 48:
			nextLayerProtocol = new TopLayerProtocol("MHRP", 4);
			break;
		case 49:
			nextLayerProtocol = new TopLayerProtocol("BNA", 4);
			break;
		case 50:
			nextLayerProtocol = new TopLayerProtocol("ESP", 3);
			break;
		case 51:
			nextLayerProtocol = new TopLayerProtocol("AH", 3);
			break;
		case 52:
			nextLayerProtocol = new TopLayerProtocol("I-NLSP", 3);
			break;
		case 53:
			nextLayerProtocol = new TopLayerProtocol("SWIPE", 3);
			break;
		case 54:
			nextLayerProtocol = new TopLayerProtocol("NARP", 3);
			break;
		case 55:
			nextLayerProtocol = new TopLayerProtocol("MOBILE", 3);
			break;
		case 56:
			nextLayerProtocol = new TopLayerProtocol("TLSP", 4);
			break;
		case 57:
			nextLayerProtocol = new TopLayerProtocol("SKIP", 4);
			break;
		case 58:
			nextLayerProtocol = new TopLayerProtocol("IPv6-ICMP", 3);
			break;
		case 59:
			nextLayerProtocol = new TopLayerProtocol("IPv6-NoNxt", 3);
			break;
		case 60:
			nextLayerProtocol = new TopLayerProtocol("IPv6-Opts", 3);
			break;
		case 62:
			nextLayerProtocol = new TopLayerProtocol("CFTP", 4);
			break;
		case 64:
			nextLayerProtocol = new TopLayerProtocol("SAT-EXPAK", 4);
			break;
		case 65:
			nextLayerProtocol = new TopLayerProtocol("KRYPTOLAN", 4);
			break;
		case 66:
			nextLayerProtocol = new TopLayerProtocol("RVD", 4);
			break;
		case 67:
			nextLayerProtocol = new TopLayerProtocol("IPPC", 4);
			break;
		case 69:
			nextLayerProtocol = new TopLayerProtocol("SAT-MON", 4);
			break;
		case 70:
			nextLayerProtocol = new TopLayerProtocol("VISA", 4);
			break;
		case 71:
			nextLayerProtocol = new TopLayerProtocol("IPCV", 3);
			break;
		case 72:
			nextLayerProtocol = new TopLayerProtocol("CPNX", 4);
			break;
		case 73:
			nextLayerProtocol = new TopLayerProtocol("CPHB", 4);
			break;
		case 74:
			nextLayerProtocol = new TopLayerProtocol("WSN", 3);
			break;
		case 75:
			nextLayerProtocol = new TopLayerProtocol("PVP", 4);
			break;
		case 76:
			nextLayerProtocol = new TopLayerProtocol("BR-SAT-MON", 4);
			break;
		case 77:
			nextLayerProtocol = new TopLayerProtocol("SUN-ND", 4);
			break;
		case 78:
			nextLayerProtocol = new TopLayerProtocol("WB-MON", 4);
			break;
		case 79:
			nextLayerProtocol = new TopLayerProtocol("WB-EXPAK", 4);
			break;
		case 80:
			nextLayerProtocol = new TopLayerProtocol("ISO-IP", 3);
			break;
		case 81:
			nextLayerProtocol = new TopLayerProtocol("VMTP", 4);
			break;
		case 82:
			nextLayerProtocol = new TopLayerProtocol("SECURE-VMTP", 4);
			break;
		case 83:
			nextLayerProtocol = new TopLayerProtocol("VINES", 4);
			break;
		case 84:
			nextLayerProtocol = new TopLayerProtocol("TTP", 4);
			break;
		case 85:
			nextLayerProtocol = new TopLayerProtocol("NSFNET-IGP", 4);
			break;
		case 86:
			nextLayerProtocol = new TopLayerProtocol("DGP", 3);
			break;
		case 87:
			nextLayerProtocol = new TopLayerProtocol("TCF", 4);
			break;
		case 88:
			nextLayerProtocol = new TopLayerProtocol("EIGRP", 3);
			break;
		case 89:
			nextLayerProtocol = new TopLayerProtocol("OSPF", 3);
			break;
		case 90:
			nextLayerProtocol = new TopLayerProtocol("Sprite-RPC", 4);
			break;
		case 91:
			nextLayerProtocol = new TopLayerProtocol("LARP", 2);
			break;
		case 92:
			nextLayerProtocol = new TopLayerProtocol("MTP", 2);
			break;
		case 93:
			nextLayerProtocol = new TopLayerProtocol("AX.25", 2);
			break;
		case 94: // IPIP
			nextLayerProtocol = new IPv4Protocol();
			break;
		case 95:
			nextLayerProtocol = new TopLayerProtocol("MICP", 3);
			break;
		case 96:
			nextLayerProtocol = new TopLayerProtocol("SCC-SP", 4);
			break;
		case 97:// ETHERIP
			nextLayerProtocol = new EthernetProtocol();
			break;
		case 98:
			nextLayerProtocol = new TopLayerProtocol("ENCAP", 4);
			break;
		case 100:
			nextLayerProtocol = new TopLayerProtocol("GMTP", 2);
			break;
		case 101:
			nextLayerProtocol = new TopLayerProtocol("IFMP", 4);
			break;
		case 102:
			nextLayerProtocol = new TopLayerProtocol("PNNI", 4);
			break;
		case 103:
			nextLayerProtocol = new TopLayerProtocol("PIM", 3);
			break;
		case 104:
			nextLayerProtocol = new TopLayerProtocol("ARIS", 3);
			break;
		case 105:
			nextLayerProtocol = new TopLayerProtocol("SCPS", 4);
			break;
		case 106:
			nextLayerProtocol = new TopLayerProtocol("QNX", 4);
			break;
		case 107:
			nextLayerProtocol = new TopLayerProtocol("A/N", 3);
			break;
		case 108:
			nextLayerProtocol = new TopLayerProtocol("IPComp", 3);
			break;
		case 109:
			nextLayerProtocol = new TopLayerProtocol("SNP", 3);
			break;
		case 110:
			nextLayerProtocol = new TopLayerProtocol("Compaq-Peer", 4);
			break;
		case 111:
			nextLayerProtocol = new TopLayerProtocol("IPX-in-IP", 3);
			break;
		case 112:
			nextLayerProtocol = new TopLayerProtocol("VRRP", 3);
			break;
		case 113:
			nextLayerProtocol = new TopLayerProtocol("PGM", 4);
			break;
		case 115: // L2TP
			// TODO nextLayerProtocol = new ;
			break;
		case 116:
			nextLayerProtocol = new TopLayerProtocol("DDX", 3);
			break;
		case 117:
			nextLayerProtocol = new TopLayerProtocol("IATP", 4);
			break;
		case 118:
			nextLayerProtocol = new TopLayerProtocol("STP", 4);
			break;
		case 119:
			nextLayerProtocol = new TopLayerProtocol("SRP", 2);
			break;
		case 120:
			nextLayerProtocol = new TopLayerProtocol("UTI", 4);
			break;
		case 121:
			nextLayerProtocol = new TopLayerProtocol("SMP", 4);
			break;
		case 122:
			nextLayerProtocol = new TopLayerProtocol("SM", 4);
			break;
		case 123:
			nextLayerProtocol = new TopLayerProtocol("PTP", 4);
			break;
		case 124:
			nextLayerProtocol = new TopLayerProtocol("ISIS", 4);
			break;
		case 125:
			nextLayerProtocol = new TopLayerProtocol("FIRE", 3);
			break;
		case 126:
			nextLayerProtocol = new TopLayerProtocol("CRTP", 4);
			break;
		case 127:
			nextLayerProtocol = new TopLayerProtocol("CRUDP", 4);
			break;
		case 128:
			nextLayerProtocol = new TopLayerProtocol("SSCOPMCE", 4);
			break;
		case 129:
			nextLayerProtocol = new TopLayerProtocol("IPLT", 3);
			break;
		case 130:
			nextLayerProtocol = new TopLayerProtocol("SPS", 4);
			break;
		case 131: // PIPE
			nextLayerProtocol = new IPv4Protocol();
			break;
		case 132: // SCTP
			nextLayerProtocol = new SctpProtocol();
			break;
		case 133:
			nextLayerProtocol = new TopLayerProtocol("FC", 2);
			break;
		case 134:
			nextLayerProtocol = new TopLayerProtocol("RSVP-E2E-IGNORE", 3);
			break;
		case 135:
			nextLayerProtocol = new TopLayerProtocol("Mobility Header", 3);
			break;
		case 136: // UDPLite
			nextLayerProtocol = new UdpProtocol();
			break;
		case 137:
			nextLayerProtocol = new TopLayerProtocol("MPLS-in-IP", 4);
			break;
		case 138:
			nextLayerProtocol = new TopLayerProtocol("MANET", 3);
			break;
		case 139:
			nextLayerProtocol = new TopLayerProtocol("HIP", 3);
			break;
		case 140:
			nextLayerProtocol = new TopLayerProtocol("Shim6", 4);
			break;
		case 141:
			nextLayerProtocol = new TopLayerProtocol("WESP", 3);
			break;
		case 142:
			nextLayerProtocol = new TopLayerProtocol("ROHC", 4);
			break;
		default:
			System.out.println("next protocol in " + name + ": " + nextProto);
			nextLayerProtocol = null;
			break;
		}
	}

}
