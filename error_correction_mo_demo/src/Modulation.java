import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.zip.CRC32;

public class Modulation extends Thread {
    private int counter = 0;
    private HammingCode hammingCode;

    Modulation(HammingCode hammingCode) {
        this.hammingCode = hammingCode;
    }

    private void receiveFrameAndModulation() {

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
                    System.out.println("*********************************Modulation*************************************");
                    counter++;
                    sIP = packet.getHeader(ip).source();
                    sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    dIP = packet.getHeader(ip).destination();
                    destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    System.out.println(packet);


                    byte[] packetBytes = NetworkHandler.getInstance().getBytes(packet.getByteArray(0, packet.size()), 0, packet.size());
                    byte[] newPayload = hammingCode.modulatorDriver(udp.getPayload());
                    int append = (newPayload.length - udp.getPayload().length);
                    byte[] byteBuffers = new byte[packet.size() + append + 3];
                    System.arraycopy(packet.getByteArray(0, packet.size()), 0, byteBuffers, 0, packet.size());
                    //udp payload
                    System.arraycopy(newPayload, 0, byteBuffers, 42, newPayload.length);
                    //udp payload


                    //ip total
                    short tempIpTotal = 0;
                    tempIpTotal = (short) (ip.length() + (newPayload.length - udp.getPayload().length));
                    byte[] ipTotal;
                    ipTotal = ByteBuffer.allocate(2).putShort(tempIpTotal).array();
                    System.arraycopy(ipTotal, 0, byteBuffers, 16, ipTotal.length);
                    //ip total

                    //ip header check sum
                    byte[] oldChecksumIP = NetworkHandler.getInstance().getBytes(packetBytes, 14, 33);
                    oldChecksumIP[24 - 14] = 0;
                    oldChecksumIP[25 - 14] = 0;
                    short newCheckSumIP = Checksum.calculateChecksum(oldChecksumIP);
                    byte[] byteNewCheckSumIP = ByteBuffer.allocate(2).putShort(newCheckSumIP).array();
                    System.arraycopy(byteNewCheckSumIP, 0, byteBuffers, 14, byteNewCheckSumIP.length);
                    //ip header check sum


                    //udp total
                    short tempUDPTotal;
                    tempUDPTotal = (short) (udp.length() + (newPayload.length - udp.getPayload().length));

                    byte[] udpTotal;
                    udpTotal = ByteBuffer.allocate(2).putShort(tempUDPTotal).array();
                    System.arraycopy(udpTotal, 0, byteBuffers, 38, udpTotal.length);
                    //udp total

                    //udp header check sum
                    byte[] oldChecksumUdp;

                    oldChecksumUdp = NetworkHandler.getInstance().getBytes(packetBytes, 34, packetBytes.length);
                    oldChecksumUdp[40 - 34] = 0;
                    oldChecksumUdp[41 - 34] = 0;
                    short newCheckSumUdp = Checksum.calculateChecksum(oldChecksumUdp);
                    byte[] byteNewCheckSumUdp = ByteBuffer.allocate(2).putShort(newCheckSumUdp).array();
                    System.arraycopy(byteNewCheckSumUdp, 0, byteBuffers, 40, byteNewCheckSumUdp.length);
                    //udp header check sum


                    //CRC32
                    CRC32 crc = new CRC32();
                    crc.update(byteBuffers);

                    byte[] crcBytes = intToBytes((int) crc.getValue());

                    System.arraycopy(crcBytes, 0, byteBuffers, byteBuffers.length - 4, crcBytes.length);
                    //CRC32
                    NetworkHandler.getInstance().sendFrameForLoopBack(byteBuffers, ethernet);
                    byteBuffers = null;
                    packetBytes = null;
                    packet = null;
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


    public byte[] intToBytes(int x) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(x);
        return buffer.array();
    }
    @Override
    public void run() {
        super.run();
        receiveFrameAndModulation();
    }
}
