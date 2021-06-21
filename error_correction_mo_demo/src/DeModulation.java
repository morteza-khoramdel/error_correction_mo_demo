import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.IOException;
import java.nio.ByteBuffer;

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

                    byte[] newPayload = hammingCode.demodulatorDriver(udp.getPayload());

                    ByteBuffer byteBuffers = ByteBuffer.allocate(packet.size() - (newPayload.length - udp.getPayload().length));
                    packet.setByteBuffer(packet.size() - (newPayload.length - udp.getPayload().length) ,byteBuffers);
                    packet.setSize(packet.size() - (newPayload.length - udp.getPayload().length));
                    //udp payload
                    packet.setByteArray(42, newPayload);
                    //udp payload


                    //ip total
                    short tempIpTotal = 0;
                    tempIpTotal = (short) (ip.length() - (newPayload.length - udp.getPayload().length));
                    byte[] ipTotal;
                    ipTotal = ByteBuffer.allocate(2).putShort(tempIpTotal).array();
                    packet.setByteArray(16, ipTotal);
                    //ip total

                    //ip header check sum
                    byte[] oldChecksumIP = packet.getByteArray(14, 33);
                    oldChecksumIP[24 - 14] = 0;
                    oldChecksumIP[25 - 14] = 0;
                    boolean newCheckSumIP = Checksum.checkChecksum(oldChecksumIP);
                    if(!newCheckSumIP) {
                        //drop packet
                        //finish
                    }

                    //ip header check sum


                    //udp total
                    short tempUDPTotal;
                    tempUDPTotal = (short) (ip.length() - (newPayload.length - udp.getPayload().length));

                    byte[] udpTotal;
                    udpTotal = ByteBuffer.allocate(2).putShort(tempUDPTotal).array();
                    packet.setByteArray(38, udpTotal);
                    //udp total

                    //udp header check sum
                    System.out.println("totlal size is : " + packet.size());
                    byte[] oldChecksumUdp;
                    oldChecksumUdp = packet.getByteArray(34, packet.size() );
                    oldChecksumUdp[40 - 34] = 0;
                    oldChecksumUdp[41 - 34] = 0;
                    boolean newCheckSumUdp = Checksum.checkChecksum(oldChecksumUdp);
                    if(!newCheckSumUdp){
                        //drop packet
                        //finish
                    }

                    //udp header check sum
                    System.out.println(packet);


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
