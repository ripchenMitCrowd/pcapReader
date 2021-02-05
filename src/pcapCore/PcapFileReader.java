package pcapCore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.channels.ReadableByteChannel;
import java.util.HashMap;

public class PcapFileReader {

	private File pcapFile;
	private HashMap<Integer, Session> sessions = new HashMap<>();

	public PcapFileReader(File file) {
		pcapFile = file;
	}

	public void readPcapFile() {
		if (pcapFile == null) {
			System.out.println("pcapFile not set -> stop");
			return;
		}

		System.out.println("-------- reading: " + pcapFile.getName() + " --------");
		try (ReadableByteChannel channel = new FileInputStream(pcapFile).getChannel()) {
			PcapHeader header = new PcapHeader(channel);
			if (!header.isValid()) {
				System.out.println("invalid pcap header -> stop");
				return;
			}
			PcapPacket packet;
			while ((packet = PcapPacket.readNextPacket(channel, header)) != null) {
				if (!packet.isPcapNgBlock()) {
					final int id = packet.hashCode();
					sessions.computeIfAbsent(packet.hashCode(), val -> new Session(id)).addPacket(packet);
				}
			}
		} catch (FileNotFoundException e) {
			System.out.println("pcap file " + pcapFile.getPath() + " does not exist or is not a file");
			e.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		System.out.println("Sessions: " + sessions.size());
		sessions.values().forEach(s -> System.out.println(s.toString()));
	}

}
