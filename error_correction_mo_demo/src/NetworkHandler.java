import com.trilead.ssh2.Connection;
import com.trilead.ssh2.Session;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.protocol.lan.Ethernet;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


class NetworkHandler {
    private static NetworkHandler networkhandler = new NetworkHandler();
    FileWriter myWriter;
    Pcap pcap;
    Pcap loopBackPcap;
    private Connection newConn;
    private Session session;
    byte[] src_mac;


    private NetworkHandler() {
    }

    static NetworkHandler getInstance() {
        return networkhandler;
    }

    void initForAll() {
        File myError = new File("myError.txt");
//        newConnectionWithPassword("192.168.1.1", "morteza", "s5560s4note3s7edge");
        try {
            myWriter = new FileWriter("myError.txt");
//            this.session = newConn.openSession();
//            this.session.execCommand("ifconfig udpSafe:0 127.0.0.2 netmask 255.0.0.0 up");
//            this.session.execCommand("route add -host 127.0.0.3 dev udpSafe");

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

    void initForUdpSafe() {

        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
        // NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }

        PcapIf device = alldevs.get(6); // init loopback

        // Initialize Network-Interface
        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        loopBackPcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

    }

    void sendFrameForLoopBack(byte[] frame, Ethernet ethernet) {

        // create Ethernet Header
        byte[] type = ByteBuffer.allocate(2).putShort((short) ethernet.type()).array();
        frame = ArrayConverter.concatenate(ethernet.destination(), ethernet.source(), type, frame);
        // Send EAPOL-Frame
        if (pcap.sendPacket(frame) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }
    }

    public void newConnectionWithPassword(String host, String username, String passwd) {
        newConn = new Connection(host);
        try {
            newConn.connect(); // Ignoring ConnectionInfo returned value.
            newConn.authenticateWithPassword(username, passwd);
        } catch (IOException ioe) {
            newConn.close();
            ioe.printStackTrace();

        }
    }

    public Connection getConnection() {
        return newConn;
    }

    public Session getSession() {
        return session;
    }

    byte[] getBytes(byte[] bytesA, int start, int end) {
        byte[] bytesFinal = new byte[end - start];
        System.arraycopy(bytesA, start, bytesFinal, 0, bytesFinal.length);
        return bytesFinal;
    }


}