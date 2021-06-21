import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.IOException;

public class DeModulation extends Thread {

    private int counter = 0;
    private HammingCode hammingCode;

    DeModulation(HammingCode hammingCode) {
        this.hammingCode = hammingCode;
    }

    private synchronized void deModulationAndSendUpper(HammingCode hammingCode) {
        StringBuilder errbuf = new StringBuilder();
        NetworkHandler.getInstance().pcap.loop(-1, (JPacketHandler<StringBuilder>) (packet, ss) -> {
            Udp udp = new Udp();
            Ip4 ip = new Ip4();
            Ethernet ethernet = new Ethernet();
            byte[] sIP;
            byte[] dIP;
            String sourceIP = "";
            String destIP = "";
            String destEthernet = "";
            try {


                if (packet.hasHeader(ip) && packet.hasHeader(udp) && packet.hasHeader(ethernet)) {
                    counter++;
                    sIP = packet.getHeader(ip).source();
                    sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    dIP = packet.getHeader(ip).destination();
                    destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    System.out.println(packet);
                    //TODO DEMODULATION
                }


            } catch (Exception e) {
                try {

                    NetworkHandler.getInstance().myWriter.write(e.getMessage() + "\n");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }

            }
        }, errbuf);
        try {
            NetworkHandler.getInstance().myWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        super.run();
        deModulationAndSendUpper(hammingCode);
    }
}
