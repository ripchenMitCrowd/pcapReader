package pcapTest;

import java.io.File;
import java.io.FilenameFilter;

import pcapCore.PcapFileReader;

public class Main {

	public static void main(String[] args) {
		FilenameFilter filter = (new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				return (name.endsWith(".pcap") || name.endsWith(".pcapng"));
			}
		});
		for (File f : new File(".").listFiles(filter)) {
			PcapFileReader reader = new PcapFileReader(f);
			reader.readPcapFile();
		}
	}

}
