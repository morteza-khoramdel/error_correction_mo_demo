import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;



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
        try(Scanner scanner = new Scanner(System.in)) {
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

    byte[] receiveFrame() {
        StringBuilder errbuf = new StringBuilder();
        pcap.loop(-1, (JPacketHandler<StringBuilder>) (packet, ss) -> {

            // counter to count the number of packet
            // in each pcap file
            Udp udp = new Udp();
            Ip4 ip = new Ip4();
            byte[] sIP = new byte[4];
            byte[] dIP = new byte[4];
            byte[] sٍEthernet = new byte[8];
            byte[] dٍEthernet = new byte[8];
            String sourceIP = "";
            String destIP = "";
            String sourceٍEthernet= "";
            String destEthernet = "";
            Ethernet  ethernet = new Ethernet();

            if(packet.hasHeader(ip) && packet.hasHeader(udp) && packet.hasHeader(ethernet)){
                sIP = packet.getHeader(ip).source();
                sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                dIP = packet.getHeader(ip).destination();
                destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
//                sourceٍEthernet = org.jnetpcap.packet.format.FormatUtils.ip(sٍEthernet);
//                destEthernet = org.jnetpcap.packet.format.FormatUtils.ip(dٍEthernet);

//                System.out.println("Ethernet " + sourceٍEthernet +"    " +destEthernet);
                System.out.println("  *  " + sourceIP + "  *  " + destIP);
                System.out.println("Source IP :" + sourceIP);
                System.out.println("Destination IP :" + destIP);

                if(udp.source() == 80){
                    System.out.println("HTTP protocol");
                } else if(udp.source() == 23) {
//                    System.out.println("Telnet protocol");////////////////////////////////////////////////
                }
            }
        }, errbuf);

        return rcvframe;
    }

    public void closeCon() {

        pcap.close();

    }

}