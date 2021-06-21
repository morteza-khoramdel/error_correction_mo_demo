import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;




class NetworkHandler {
    private static NetworkHandler networkhandler = new NetworkHandler();
    private int counter = 0;
    private FileWriter myWriter;
    private Pcap pcap;

    public byte[] src_mac;

    private NetworkHandler() {
    }

    static NetworkHandler getInstance() {
        return networkhandler;
    }

    void init() {
        File myError = new File("myError.txt");
        try {
            myWriter = new FileWriter("myError.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
        // NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs

        int index; // Device Index

        /***************************************************************************
         * First get a list of devices on this system
         **************************************************************************/
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }

        /*****************************************
         * Show all network interfaces
         *****************************************/

        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device.getDescription()
                    : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        /***************************************
         Select network interfaces
         */
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                try {
                    System.out.print("Which [number] of Network-Adapter to use: ");
                    index = Integer.parseInt(scanner.next());
                    if (index >= 0 && index < i) {
                        break;
                    } else {
                        System.out.println("Incorrect, retry...");
                    }
                } catch (NumberFormatException e) {
                    System.out.println("Incorrect, retry...");
                }
            }
        }

        PcapIf device = alldevs.get(index); // We know we have atleast 1 device

        System.out.printf("\nChoosing '%s' on your behalf:\n",
                (device.getDescription() != null) ? device.getDescription() : device.getName());

        // Initialize Network-Interface

        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        try {
            src_mac = device.getHardwareAddress();
        } catch (IOException e) {
            System.out.println("Can't get Source-MAC!");
            e.printStackTrace();
        }

    }

    private void sendFrame(byte[] frame, Ethernet ethernet) {

        // create Ethernet Header
        byte[] type = ByteBuffer.allocate(2).putShort((short) ethernet.type()).array();
        frame = ArrayConverter.concatenate(ethernet.destination(), ethernet.source(), type, frame);

        // Send EAPOL-Frame
        if (pcap.sendPacket(frame) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }
    }

    void receiveFrameAndSendFrame(HammingCode hammingCode) {
        StringBuilder errbuf = new StringBuilder();
        pcap.loop(-1, (JPacketHandler<StringBuilder>) (packet, ss) -> {
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
                    byte[] packetBytes = getBytes(packet.getByteArray(0, packet.size()), 0, packet.size());
                    byte[] newPayload = hammingCode.modulatorDriver(udp.getPayload());
                    int append = (newPayload.length - udp.getPayload().length);
                    byte[] byteBuffers = new byte[packet.size() + append];
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
                    byte[] oldChecksumIP = getBytes(packetBytes, 14, 33);
                    oldChecksumIP[24 - 14] = 0;
                    oldChecksumIP[25 - 14] = 0;
                    short newCheckSumIP = Checksum.calculateChecksum(oldChecksumIP);
                    byte[] byteNewCheckSumIP = ByteBuffer.allocate(2).putShort(newCheckSumIP).array();
                    System.arraycopy(byteNewCheckSumIP, 0, byteBuffers, 14, byteNewCheckSumIP.length);
                    //ip header check sum


                    //udp total
                    short tempUDPTotal;
                    tempUDPTotal = (short) (ip.length() + (newPayload.length - udp.getPayload().length));

                    byte[] udpTotal;
                    udpTotal = ByteBuffer.allocate(2).putShort(tempUDPTotal).array();
                    System.arraycopy(udpTotal, 0, byteBuffers, 38, udpTotal.length);
                    //udp total

                    //udp header check sum
                    System.out.println("totlal size is : " + packet.size());
                    byte[] oldChecksumUdp;

                    oldChecksumUdp = getBytes(packetBytes, 34, packetBytes.length);
                    oldChecksumUdp[40 - 34] = 0;
                    oldChecksumUdp[41 - 34] = 0;
                    short newCheckSumUdp = Checksum.calculateChecksum(oldChecksumUdp);
                    byte[] byteNewCheckSumUdp = ByteBuffer.allocate(2).putShort(newCheckSumUdp).array();
                    System.arraycopy(byteNewCheckSumUdp, 0, byteBuffers, 40, byteNewCheckSumUdp.length);
                    //udp header check sum
                    sendFrame(byteBuffers, ethernet);
                    byteBuffers = null;
                    packetBytes = null;
                    packet = null;
                }


            } catch (Exception e) {
                try {

                    myWriter.write(e.getMessage() + "\n");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }

            }
        }, errbuf);
        try {
            myWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private byte[] getBytes(byte[] bytesA, int start, int end) {
        byte[] bytesFinal = new byte[end - start];
        System.arraycopy(bytesA, start, bytesFinal, 0, bytesFinal.length);
        return bytesFinal;
    }


}