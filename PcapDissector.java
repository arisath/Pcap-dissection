import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.lan.Ethernet;
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
    static final Ethernet ethernet = new Ethernet();
    static final Http http = new Http();
    static final Tcp tcp = new Tcp();
    static final Udp udp = new Udp();
    static final Ip4 ip = new Ip4();
    static final Ip6 ip6 = new Ip6();
    static final WebImage webimage = new WebImage();

    static int numberOfPacketsSent = 0;
    static int numberOfPacketsReceived = 0;
    static int numberOfPackets = 0;

    static int numberOfEthernetPackets = 0;
    static int numberOfARP = 0;

    static int numberOfIPpackets = 0;

    static int numberOfTcpPackets = 0;
    static int numberOfSYN;
    static int numberOfSYNACK;
    static int numberOfACK;
    static int numberOfPSHACK;
    static int numberOfFINPSHACK;
    static int numberOfFINACK;
    static int numberOfRST;

    static int numberOfSslTls;
    static int numberOfUdpPackets = 0;
    static int numberOfDNS;

    static int numberOfHTTPpackets = 0;
    static int numberOfGETS = 0;
    static int numberOfPosts = 0;
    static int numberOfImages = 0;

    static String macAddress = "";

    static HashSet<String> ipAddressesVisited = new HashSet<String>();
    static TreeSet<Integer> portsUsed = new TreeSet<>();
    static HashMap<String, Integer> imageTypes = new HashMap<String, Integer>();


    static PrintWriter writer;

    public static void main(String[] args)
    {

        try
        {
            macAddress = getMacAddress();

            writer = new PrintWriter("Report.txt", "UTF-8");

            String pcapName = "fooo.pcap";

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

                    if (packet.hasHeader(ethernet) )
                    {
                        processEthernetheader();
                    }
                    if (packet.hasHeader(ip))
                    {
                        processIPheader();

                        if (packet.hasHeader(tcp))
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

            };

            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, " *");
            pcap.close();

            printTrafficStatistics();
            printPortsUsed(portsUsed);
            printIPaddressesVisited(ipAddressesVisited);
            printTCPflagsStatistics();
            printImageTypes();
            System.out.println(numberOfEthernetPackets);
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

    static void processEthernetheader()
    {
        numberOfEthernetPackets++;

        if ((new String(FormatUtils.hexdump(ethernet.getHeader())).substring(45, 50)).equals("08 06"))
        {
            numberOfARP++;
        }
        String sourceMac = FormatUtils.mac(ethernet.source());

        String destinationMac = FormatUtils.mac(ethernet.destination());

        separateIngoingOutgoing(sourceMac, destinationMac);

    }

    static void processIPheader()
    {
        numberOfIPpackets++;

        String sourceIP = FormatUtils.ip(ip.source());

        String destinationIP = FormatUtils.ip(ip.destination());

        getDestinationAddress(sourceIP, destinationIP);
    }

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


    static void processTCPheader()
    {
        numberOfTcpPackets++;

        int sport = tcp.source();

        int dport = tcp.destination();

        portsUsed.add(sport);

        portsUsed.add(dport);

        processTCPflags();

        processPorts(sport, dport);
    }

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

    static void processUDPheader()
    {
        numberOfUdpPackets++;

        int sport = udp.source();

        int dport = udp.destination();

        portsUsed.add(sport);

        portsUsed.add(dport);

        processPorts(sport, dport);
    }

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

    static void printImageTypes()
    {
        writer.printf("%s %d %s \n", "Found ", numberOfImages, " images:");

        for (Map.Entry entry : imageTypes.entrySet())
        {
            writer.printf("%-4s %s %d \n", entry.getKey(), " ", entry.getValue());
        }
    }

    static void getDestinationAddress(String sourceIP, String destinationIP)
    {
        if (sourceIP.equals(macAddress))
        {
            ipAddressesVisited.add(destinationIP);
        }
    }

    static void printPortsUsed(TreeSet<Integer> portsUsed)
    {
        writer.println();

        writer.println("Ports utilised:");

        int i = 0;

        for (int port : portsUsed)
        {
            i++;

            writer.printf("%5d %s", port, " ");

            if (i % 18 == 0)
            {
                writer.println();
            }
        }
        writer.println();
    }

    static void printIPaddressesVisited(HashSet<String> ipAddressesVisited)
    {
        writer.println();

        writer.println("IP addresses visited:");

        int i = 0;

        for (String ip : ipAddressesVisited)
        {
            i++;

            writer.printf("%-16s %s", ip, " ");

            if (i % 7 == 0)
            {
                writer.println();
            }
        }

        writer.println();
    }

    static void printTrafficStatistics()
    {
        writer.printf("%-46s %s %d \n", "Total number of packets in pcap", ": ", numberOfPackets);
        writer.printf("%-33s %-6s %s %d %s %.2f %s \n", "Number of packets sent from", macAddress, ": ", numberOfPacketsSent, " ", ((float) numberOfPacketsSent / numberOfPackets) * 100, "%");
        writer.printf("%-33s %-6s %s %d %s %.2f %s \n", "Number of packets sent to", macAddress, ": ", numberOfPacketsReceived, " ", ((float) numberOfPacketsReceived / numberOfPackets) * 100, "%");
        writer.printf("%-45s  %s %d \n", "ARP packets", ": ", numberOfARP);

        writer.printf("%-45s  %s %d \n", "TCP packets", ": ", numberOfTcpPackets);
        writer.printf("%-45s  %s %d \n", "SSL/TLS packets", ": ", numberOfSslTls);

        writer.printf("%-45s  %s %d \n", "UDP packets", ": ", numberOfUdpPackets);
        writer.printf("%-45s  %s %d \n", "DNS packets", ": ", numberOfDNS);
        writer.printf("%-45s  %s %d \n", "HTTP packets", ": ", numberOfHTTPpackets);
        writer.printf("%-45s  %s %d \n", "Number of  GET requests", ": ", numberOfGETS);
        writer.printf("%-45s  %s %d \n", "Number of POST requests", ": ", numberOfPosts);
    }

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

