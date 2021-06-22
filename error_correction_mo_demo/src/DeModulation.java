import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.zip.CRC32;

public class DeModulation extends Thread {

    private int counter = 0;
    private HammingCode hammingCode;
    private String crcString;

    DeModulation(HammingCode hammingCode, String crcString) {
        this.crcString = crcString;
        this.hammingCode = hammingCode;
    }

    private  void deModulationAndSendUpper() {
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
                    System.out.println("*********************************DeModulation*************************************");
                    counter++;
                    sIP = packet.getHeader(ip).source();
                    sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    dIP = packet.getHeader(ip).destination();
                    destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    System.out.println(packet);

////////////////////////////////////////////////////////////////////////////Specify the byteBuffers in demodulator
                    //crc for demodulation
                    CRC32 crc = new CRC32();
                    crc.update(byteBuffers);

                    byte[] crcBytes = longToBytes(crc.getValue());

                    System.arraycopy(crcBytes, 0, byteBuffers, packet.size() + append, crcBytes.length);
                    if(crc.getValue() == 0){
                        System.out.println("Continue");
                    }else {
                        System.out.println("Packet Droped");

                    }
/////////////////////////////////////////////////////////////////////////////
                    byte[] packetBytes = NetworkHandler.getInstance().getBytes(packet.getByteArray(0, packet.size()), 0, packet.size());

                    byte[] mainPayload = new byte[udp.getPayloadLength() - crcBytes.length];
                    System.arraycopy(udp.getPayload(), 0, mainPayload, 0, mainPayload.length);

                    byte[] newPayload = hammingCode.demodulatorDriver(mainPayload);
                    int append = (mainPayload.length - newPayload.length);
                    byte[] byteBuffers = new byte[mainPayload.length - append];

                    //udp payload
                    System.arraycopy(newPayload, 0, byteBuffers, 42, newPayload.length);
                    //udp payload

                    //ip total
                    short tempIpTotal = 0;
                    tempIpTotal = (short) (ip.length() + (mainPayload.length - newPayload.length));
                    byte[] ipTotal;
                    ipTotal = ByteBuffer.allocate(2).putShort(tempIpTotal).array();
                    System.arraycopy(ipTotal, 0, byteBuffers, 16, ipTotal.length);
                    //ip total


                    //ip header check sum
                    byte[] oldChecksumIP = NetworkHandler.getInstance().getBytes(packetBytes, 14, 33);
                    boolean newCheckSumIP = Checksum.checkChecksum(oldChecksumIP);
                    if (!newCheckSumIP) {
                        packet = null;
                        //drop packet
                        //finish
                    }
                    //ip header check sum

                    //udp total
                    short tempUDPTotal;
                    tempUDPTotal = (short) (ip.length() - (mainPayload.length - newPayload.length));

                    byte[] udpTotal;
                    udpTotal = ByteBuffer.allocate(2).putShort(tempUDPTotal).array();
                    System.arraycopy(udpTotal, 0, byteBuffers, 38, udpTotal.length);
                    //udp total

                    //udp header check sum
                    byte[] oldChecksumUdp;
                    oldChecksumUdp = NetworkHandler.getInstance().getBytes(packetBytes, 34, packetBytes.length);
                    boolean newCheckSumUdp = Checksum.checkChecksum(oldChecksumUdp);
                    if (!newCheckSumUdp) {
                        //drop packet
                        packet = null;
                    }
                    //udp header check sum
                }


            } catch (Exception e) {
                try {
                    System.out.println("Packet Drop");
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

    public byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }
    @Override
    public void run() {
        super.run();
        deModulationAndSendUpper();
    }
}
