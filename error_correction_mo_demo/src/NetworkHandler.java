import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.Scanner;
import java.util.concurrent.ArrayBlockingQueue;


//TODO


public class NetworkHandler {
    private static NetworkHandler networkhandler = new NetworkHandler();

    Pcap pcap;

    public byte[] dst_mac = EapConstants.BROADCAST_ADDRESS;

    public byte[] src_mac;

    public byte[] frametype = EapConstants.ETHERTYPE_EAP;

    public byte[] rcvframe;

    Queue<PcapPacket> queue = new ArrayBlockingQueue<PcapPacket>(20);

    private NetworkHandler() {
    }

    public static NetworkHandler getInstance() {
        return networkhandler;
    }

    public void init() {

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

    public void sendFrame(byte[] frame) {

        // create Ethernet Header
        frame = ArrayConverter.concatenate(dst_mac, src_mac, frametype, frame);

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
            byte[] sٍEthernet;
            byte[] dٍEthernet;
            String sourceIP = "";
            String destIP = "";
            String sourceٍEthernet = "";
            String destEthernet = "";

            if (packet.hasHeader(ip) && packet.hasHeader(udp) && packet.hasHeader(ethernet)) {
                sIP = packet.getHeader(ip).source();
                sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                dIP = packet.getHeader(ip).destination();
                destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                System.out.println(packet);
                byte[] newPayload = hammingCode.modulatorDriver(udp.getPayload());

                ByteBuffer byteBuffers = ByteBuffer.allocate(packet.size() + (newPayload.length - udp.getPayload().length));
                packet.setByteBuffer(packet.size() + (newPayload.length - udp.getPayload().length) ,byteBuffers);
                packet.setSize(packet.size() + (newPayload.length - udp.getPayload().length));
                //udp payload
                packet.setByteArray(42, newPayload);
                //udp payload


                //ip total
                short tempIpTotal = 0;
                tempIpTotal = (short) (ip.length() + (newPayload.length - udp.getPayload().length));
                byte[] ipTotal;
                ipTotal = ByteBuffer.allocate(2).putShort(tempIpTotal).array();
                packet.setByteArray(16, ipTotal);
                //ip total

                //ip header check sum
                byte[] oldChecksumIP = packet.getByteArray(14, 33);
                oldChecksumIP[24 - 14] = 0;
                oldChecksumIP[25 - 14] = 0;
                short newCheckSumIP = Checksum.calculateChecksum(oldChecksumIP);
                byte[] byteNewCheckSumIP = ByteBuffer.allocate(2).putShort(newCheckSumIP).array();
                packet.setByteArray(14, byteNewCheckSumIP);

                //ip header check sum


                //udp total
                short tempUDPTotal;
                tempUDPTotal = (short) (ip.length() + (newPayload.length - udp.getPayload().length));

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
                short newCheckSumUdp = Checksum.calculateChecksum(oldChecksumUdp);
                byte[] byteNewCheckSumUdp = ByteBuffer.allocate(2).putShort(newCheckSumUdp).array();
                packet.setByteArray(40, byteNewCheckSumUdp);

                //udp header check sum
                System.out.println(packet);




            }
        }, errbuf);
    }

    public void closeCon() {

        pcap.close();

    }




}