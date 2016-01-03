import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeSet;


class PcapDissection
{
    static String pcapName;

    static final Ethernet ethernet = new Ethernet();
    static final Http http = new Http();
    static final Tcp tcp = new Tcp();
    static final Udp udp = new Udp();
    static final Ip4 ip = new Ip4();
    static final Icmp icmp = new Icmp();
    static final Ip6 ip6 = new Ip6();
    static final WebImage webimage = new WebImage();

    static int numberOfPacketsSent;
    static int numberOfPacketsReceived;
    static int numberOfPackets;

    static int numberOfARPpackets;
    static int numberOfICMPpackets;

    static int numberOfIPpackets;

    static int numberOfTcpPackets;
    static int numberOfSYN;
    static int numberOfSYNACK;
    static int numberOfACK;
    static int numberOfPSHACK;
    static int numberOfFINPSHACK;
    static int numberOfFINACK;
    static int numberOfRST;

    static int numberOfSslTls;
    static int numberOfUdpPackets;
    static int numberOfDNS;

    static int numberOfHTTPpackets;
    static int numberOfGETS;
    static int numberOfPosts;
    static int numberOfImages;

    static String macAddress = "";

    static HashSet<String> ipAddressesVisited = new HashSet<String>();
    static TreeSet<Integer> clientPortsUsed = new TreeSet<Integer>();
    static TreeSet<Integer> serversPortsUsed = new TreeSet<Integer>();
    static HashMap<String, Integer> imageTypes = new HashMap<String, Integer>();

    static PrintWriter writer;

    public static void main(String[] args)
    {

        try
        {
            macAddress = getMacAddress();

            writer = new PrintWriter("Report.txt", "UTF-8");

            pcapName = "fooo.pcap";

            StringBuilder errbuf = new StringBuilder();

            Pcap pcap = Pcap.openOffline(pcapName, errbuf);

            if (pcap == null)
            {
                System.err.println(errbuf);

                return;
            }
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>()
            {

                public void nextPacket(PcapPacket packet, String user)
                {
                    numberOfPackets++;

                    if (packet.hasHeader(ethernet))
                    {
                        processEthernetheader();

                        if (packet.hasHeader(ip))
                        {
                            processIPheader();

                            if (packet.hasHeader(icmp))
                            {
                                numberOfICMPpackets++;
                            }
                            else if (packet.hasHeader(tcp))
                            {
                                processTCPheader();
                            }
                            else if (packet.hasHeader(udp))
                            {
                                processUDPheader();
                            }

                            if (packet.hasHeader(http))
                            {
                                processHTTPheader();

                            }

                            if (packet.hasHeader(webimage))
                            {
                                processImage();
                            }
                        }
                    }
                }

            };

            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, " *");
            pcap.close();

            printTrafficStatistics();
            printPortsUsed("Servers'  ", serversPortsUsed);
            printPortsUsed("Client's ", clientPortsUsed);
            printIPaddressesVisited(ipAddressesVisited);
            printTCPflagsStatistics();
            printImageTypes();

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally
        {
            writer.close();
        }

    }

    /**
     * Returns the MAC address of the current machine in 00:00:00:00:00:00 format
     *
     * @return
     */
    static String getMacAddress()
    {
        try
        {
            InetAddress ip2 = InetAddress.getLocalHost();

            NetworkInterface network = NetworkInterface.getByInetAddress(ip2);

            byte[] mac = network.getHardwareAddress();

            if (mac != null)
            {
                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < mac.length; i++)
                {
                    sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                }
                return sb.toString().replaceAll("-", ":");
            }
        }
        catch (UnknownHostException e)
        {
            e.printStackTrace();
        }
        catch (SocketException e)
        {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Processes the ethernet header of this packet
     */
    static void processEthernetheader()
    {
        if ((new String(FormatUtils.hexdump(ethernet.getHeader())).substring(45, 50)).equals("08 06"))
        {
            numberOfARPpackets++;
        }
        String sourceMac = FormatUtils.mac(ethernet.source());

        String destinationMac = FormatUtils.mac(ethernet.destination());

        separateIngoingOutgoing(sourceMac, destinationMac);

    }

    /**
     * Processes the IP header of this packet
     */
    static void processIPheader()
    {
        numberOfIPpackets++;

        String sourceMac = FormatUtils.mac(ethernet.source());

        String destinationIP = FormatUtils.ip(ip.destination());

        getDestinationAddress(sourceMac, destinationIP);
    }

    /**
     * Separates ingoing from outgoing traffic based on the
     * MAC addresses of the ethernet header
     *
     * @param sourceMac
     * @param destinationMac
     */
    public static void separateIngoingOutgoing(String sourceMac, String destinationMac)
    {
        if (sourceMac.equalsIgnoreCase(macAddress))
        {
            numberOfPacketsSent++;
        }
        else if (destinationMac.equalsIgnoreCase(macAddress))
        {
            numberOfPacketsReceived++;
        }
    }

    /**
     * Processes the TCP header of this packet
     */
    static void processTCPheader()
    {
        numberOfTcpPackets++;

        int sport = tcp.source();

        int dport = tcp.destination();

        addPorts(sport, dport);

        processTCPflags();

        processPorts(sport, dport);
    }

    /**
     * Processes the flags of this packet's TCP header
     * TCP Flags include: [SYN], [SYN ACK], [ACK], [PSH ACK]
     * [FIN PSH ACK], [FIN ACK], [RST]
     */
    static void processTCPflags()
    {
        if (tcp.flags_SYN() && (!tcp.flags_ACK()))
        {
            numberOfSYN++;
        }
        else if (tcp.flags_SYN() && tcp.flags_ACK())
        {
            numberOfSYNACK++;
        }
        else if (tcp.flags_ACK() && (!tcp.flags_SYN()) && (!tcp.flags_PSH()) && (!tcp.flags_FIN()) && (!tcp.flags_RST()))
        {
            numberOfACK++;
        }
        else if (tcp.flags_PSH() && (tcp.flags_ACK() && (!tcp.flags_FIN())))
        {
            numberOfPSHACK++;
        }
        else if (tcp.flags_FIN() && tcp.flags_ACK() && (!tcp.flags_PSH()))
        {
            numberOfFINACK++;
        }
        else if (tcp.flags_PSH() && (tcp.flags_ACK() && (tcp.flags_FIN())))
        {
            numberOfFINPSHACK++;
        }
        else if (tcp.flags_RST())
        {
            numberOfRST++;
        }
    }

    /**
     * Processes the ports of a packet using transport layer protocols (TCP, UDP)
     *
     * @param sport sourcePort
     * @param dport destinationPort
     */
    static void processPorts(int sport, int dport)
    {
        if (sport == 53 || dport == 53)
        {
            numberOfDNS++;
        }
        else if (sport == 443 || dport == 443)
        {
            numberOfSslTls++;
        }
    }

    /**
     * Adds the source and destination ports to the appropriate
     * Treeset based on the source and destination mac addresses
     * of the packet
     *
     * @param sport
     * @param dport
     */
    static void addPorts(int sport, int dport)
    {
        String sourceMac = FormatUtils.mac(ethernet.source());

        String destinationMac = FormatUtils.mac(ethernet.destination());

        if (sourceMac.equals(macAddress))
        {
            clientPortsUsed.add(sport);

            serversPortsUsed.add(dport);
        }
        else if (destinationMac.equals(macAddress))
        {
            clientPortsUsed.add(dport);
            
            serversPortsUsed.add(sport);
        }
    }

    /**
     * Processes the UDP header of this packet
     */
    static void processUDPheader()
    {
        numberOfUdpPackets++;

        int sport = udp.source();

        int dport = udp.destination();

        addPorts(sport, dport);

        processPorts(sport, dport);
    }

    /**
     * Processes the HTTP header of this packet
     */
    static void processHTTPheader()
    {
        numberOfHTTPpackets++;

        if (http.header().contains("GET"))
        {
            numberOfGETS++;
        }
        else if (http.header().contains("POST"))
        {
            numberOfPosts++;
        }
    }

    /**
     * Processes images transferred over HTTP
     * Images transferred over SSL/TLS will not be processed
     */
    static void processImage()
    {
        numberOfImages++;

        String imageType = http.contentTypeEnum().toString();

        Integer count = imageTypes.get(imageType);

        if (count == null)
        {
            imageTypes.put(imageType, 1);
        }
        else
        {
            imageTypes.put(imageType, count + 1);
        }
    }

    /**
     * Prints the distributions among the different image types that
     * have been downloaded in the machine
     */
    static void printImageTypes()
    {
        writer.printf("%s %d %s \n", "Found ", numberOfImages, " images (Images transferred over SSL/TLS are not included) :");

        for (Map.Entry entry : imageTypes.entrySet())
        {
            writer.printf("%-4s %s %d \n", entry.getKey(), " ", entry.getValue());
        }
    }

    /**
     * Adds the IP destination address to list of IP addresses visited
     *
     * @param sourceMac
     * @param destinationIP
     */
    static void getDestinationAddress(String sourceMac, String destinationIP)
    {
        if (sourceMac.equals(macAddress))
        {
            ipAddressesVisited.add(destinationIP);
        }
    }

    /**
     * Prints the ports that have been used
     *
     * @param portsUsed
     */
    static void printPortsUsed(String machine, TreeSet<Integer> portsUsed)
    {
        writer.println();

        writer.println(machine + " ports utilised:");

        int i = 0;

        for (int port : portsUsed)
        {
            i++;

            writer.printf("%5d  ", port);

            if (i % 18 == 0)
            {
                writer.println();
            }
        }
        writer.println();
    }

    /**
     * Prints the IP addresses that were visited
     *
     * @param ipAddressesVisited
     */
    static void printIPaddressesVisited(HashSet<String> ipAddressesVisited)
    {
        writer.println();

        writer.println("IP addresses visited:");

        int i = 0;

        for (String ip : ipAddressesVisited)
        {
            i++;

            writer.printf("%-16s  ", ip);

            if (i % 7 == 0)
            {
                writer.println();
            }
        }

        writer.println();
    }

    /**
     * Prints traffic statistics related to different protocols from different OSI layers
     * Protocols include: Ethernet, ARP, IP, TCP/UDP, SSL/TLS, DNS, HTTP
     */
    static void printTrafficStatistics()
    {
        writer.printf("Report for " + pcapName + "\n\n");
        writer.printf("%-46s %s %8d \n", "Total number of packets in pcap", ": ", numberOfPackets);
        writer.printf("%-27s %-18s %s %8d %s %.2f %s \n", "Number of packets sent from", macAddress, ": ", numberOfPacketsSent, " ", ((float) numberOfPacketsSent / numberOfPackets) * 100, "%");
        writer.printf("%-27s %-18s %s %8d %s %.2f %s \n", "Number of packets sent to", macAddress, ": ", numberOfPacketsReceived, " ", ((float) numberOfPacketsReceived / numberOfPackets) * 100, "%");
        writer.printf("%-45s  %s %8d \n", "ARP packets", ": ", numberOfARPpackets);

        writer.printf("%-45s  %s %8d \n", "TCP packets", ": ", numberOfTcpPackets);
        writer.printf("%-45s  %s %8d \n", "SSL/TLS packets", ": ", numberOfSslTls);

        writer.printf("%-45s  %s %8d \n", "UDP packets", ": ", numberOfUdpPackets);
        writer.printf("%-45s  %s %8d \n", "DNS packets", ": ", numberOfDNS);
        writer.printf("%-45s  %s %8d \n", "HTTP packets", ": ", numberOfHTTPpackets);
        writer.printf("%-45s  %s %8d \n", "Number of  GET requests", ": ", numberOfGETS);
        writer.printf("%-45s  %s %8d \n", "Number of POST requests", ": ", numberOfPosts);
    }

    /**
     * Prints the distributions among different TCP flags
     * TCP Flags include: [SYN], [SYN ACK], [ACK], [PSH ACK]
     * [FIN PSH ACK], [FIN ACK], [RST]
     */
    static void printTCPflagsStatistics()
    {
        writer.println();
        writer.println("TCP Flags distribution: ");
        writer.printf("%-12s %s %8d %5.2f %s \n", "SYN", ": ", numberOfSYN, ((float) numberOfSYN) / numberOfTcpPackets * 100, "%");
        writer.printf("%-12s %s %8d %5.2f %s \n", "SYN ACK", ": ", numberOfSYNACK, ((float) numberOfSYNACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-12s %s %8d %5.2f %s \n", "ACK", ": ", numberOfACK, ((float) numberOfACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-12s %s %8d %5.2f %s \n", "PSH ACK", ": ", numberOfPSHACK, ((float) numberOfPSHACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-12s %s %8d %5.2f %s \n", "FIN PSH ACK", ": ", numberOfFINPSHACK, ((float) numberOfFINPSHACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-12s %s %8d %5.2f %s \n", "FIN ACK", ": ", numberOfFINACK, ((float) numberOfFINACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-12s %s %8d %5.2f %s \n", "RST", ": ", numberOfRST, ((float) numberOfRST) / numberOfTcpPackets * 100, "%");
        writer.println();
    }
}

