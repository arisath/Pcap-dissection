package com.arisath.pcap;

import org.apache.commons.net.whois.WhoisClient;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.application.Html;
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
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;

import static com.arisath.pcap.Utils.printHTTPHosts;

public class PcapDissection
{
    private static final Ethernet ethernet = new Ethernet();
    private static final Http http = new Http();
    private static final Tcp tcp = new Tcp();
    private static final Udp udp = new Udp();
    private static final Ip4 ip = new Ip4();
    private static final Icmp icmp = new Icmp();
    private static final Ip6 ip6 = new Ip6();
    private static final WebImage webimage = new WebImage();
    private static final Html htm = new Html();
    static PrintWriter writer;
    private static Pcap pcap;
    private static String pcapName;
    private static int numberOfPackets;
    private static int numberOfPacketsSent;
    private static int numberOfPacketsReceived;
    private static int numberOfARPpackets;
    private static int numberOfICMPpackets;
    private static int numberOfIPpackets;
    private static int numberOfTcpPackets;
    private static int numberOfSYN;
    private static int numberOfSYNACK;
    private static int numberOfACK;
    private static int numberOfPSHACK;
    private static int numberOfFINPSHACK;
    private static int numberOfFINACK;
    private static int numberOfRST;
    private static int numberOfClientHelloPackets;
    private static int numberOfCServerHelloPackets;
    private static int numberOfSslTls;
    private static int numberOfUdpPackets;
    private static int numberOfDNS;
    private static int numberOfHTTPpackets;
    protected static int numberOfImages;
    private static HashMap<String, String> ipAddressesVisited = new HashMap<String, String>();
    private static TreeSet<Integer> clientPortsUsed = new TreeSet<Integer>();
    private static TreeSet<Integer> serversPortsUsed = new TreeSet<Integer>();
    protected static HashMap<String, Integer> imageTypes = new HashMap<String, Integer>();
    private static HashMap<String, Integer> httpRequestTypes = new HashMap<String, Integer>();
    private static HashMap<String, Integer> httpResponses = new HashMap<String, Integer>();
    private static HashMap<String, Integer> httpServers = new HashMap<String, Integer>();
    private static HashMap<String, Integer> httpReferers = new HashMap<String, Integer>();
    private static HashMap<String, Integer> httpUserAgents = new HashMap<String, Integer>();
    private static HashMap<String, Integer> httpHosts = new HashMap<String, Integer>();
    private static String macAddress = "";

    public static void main(String[] args)
    {
        try
        {
            macAddress = getMacAddress();

            writer = new PrintWriter("Report.txt", "UTF-8");

            Properties prop = Utils.loadPropertiesFile("config.properties");

            pcapName = prop.getProperty("pcapPath");

            StringBuilder errbuf = new StringBuilder();

            pcap = Pcap.openOffline(pcapName, errbuf);

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
                            } else if (packet.hasHeader(tcp))
                            {
                                processTCPheader();
                            } else if (packet.hasHeader(udp))
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

                            if (packet.hasHeader(ip6))
                            {
                                System.out.println("xx");
                            }
                        }
                    }
                }
            };

            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, " *");

            printTrafficStatistics();
            Utils.printHTTPUserAgent(httpUserAgents);
            Utils.printHTTPResponseStatistics(httpResponses);
            Utils.printHTTPServers(httpServers);
            Utils.printHTTPReferersStatistics(httpReferers);
            Utils.printHTTPRequestTypes(httpRequestTypes);
            printHTTPHosts(httpHosts);
            Utils.printImageTypes();
            printTCPflagsStatistics();
            printPortsUsed("Servers' ", serversPortsUsed);
            printPortsUsed("Client's ", clientPortsUsed);
            // resolveIPaddresses(ipAddressesVisited);
            // printIPaddressesVisited(ipAddressesVisited);

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally
        {
            pcap.close();
            writer.close();
        }

    }

    /**
     * Returns the MAC address of the current machine in 00:00:00:00:00:00 format
     *
     * @return
     */
    private static String getMacAddress()
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
        catch (UnknownHostException | SocketException e)
        {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Processes the ethernet header of this packet
     */
    private static void processEthernetheader()
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
    private static void processIPheader()
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
    private static void separateIngoingOutgoing(String sourceMac, String destinationMac)
    {
        if (sourceMac.equalsIgnoreCase(macAddress))
        {
            numberOfPacketsSent++;
        } else if (destinationMac.equalsIgnoreCase(macAddress))
        {
            numberOfPacketsReceived++;
        }
    }

    /**
     * Processes the TCP header of this packet
     */
    private static void processTCPheader()
    {
        numberOfTcpPackets++;

        int sport = tcp.source();

        int dport = tcp.destination();

        addPorts(sport, dport);

        processTCPflags();

        processPorts(sport, dport);

        if (dport == 443)
        {
            processSslTlsPackets();
        } else if (sport == 443)
        {
            processSslTlsPackets();
        }

    }

    /**
     * Processes the flags of this packet's TCP header
     * TCP Flags include: [SYN], [SYN ACK], [ACK], [PSH ACK]
     * [FIN PSH ACK], [FIN ACK], [RST]
     */
    private static void processTCPflags()
    {
        if (tcp.flags_SYN() && (!tcp.flags_ACK()))
        {
            numberOfSYN++;
        } else if (tcp.flags_SYN() && tcp.flags_ACK())
        {
            numberOfSYNACK++;
        } else if (tcp.flags_ACK() && (!tcp.flags_SYN()) && (!tcp.flags_PSH()) && (!tcp.flags_FIN()) && (!tcp.flags_RST()))
        {
            numberOfACK++;
        } else if (tcp.flags_PSH() && (tcp.flags_ACK() && (!tcp.flags_FIN())))
        {
            numberOfPSHACK++;
        } else if (tcp.flags_FIN() && tcp.flags_ACK() && (!tcp.flags_PSH()))
        {
            numberOfFINACK++;
        } else if (tcp.flags_PSH() && (tcp.flags_ACK() && (tcp.flags_FIN())))
        {
            numberOfFINPSHACK++;
        } else if (tcp.flags_RST())
        {
            numberOfRST++;
        }
    }

    /**
     * Inspects SSL/TLS packet for the client and server hello flags
     */
    private static void processSslTlsPackets()
    {

        if (tcp.getPayload().length > 0)
        {
            String clientHello = FormatUtils.hexdump(tcp.getPayload()).substring(12, 14);

            if (clientHello.equals("01"))
            {
                numberOfClientHelloPackets++;
            }

            String serverHello = FormatUtils.hexdump(tcp.getPayload()).substring(22, 24);

            if (serverHello.equals("02"))
            {
                numberOfCServerHelloPackets++;
            }
        }
    }

    /**
     * Processes the ports of a packet using transport layer protocols (TCP, UDP)
     *
     * @param sport sourcePort
     * @param dport destinationPort
     */
    private static void processPorts(int sport, int dport)
    {
        if (sport == 53 || dport == 53)
        {
            numberOfDNS++;
        } else if (sport == 443 || dport == 443)
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
    private static void addPorts(int sport, int dport)
    {
        String sourceMac = FormatUtils.mac(ethernet.source());

        String destinationMac = FormatUtils.mac(ethernet.destination());

        if (sourceMac.equals(macAddress))
        {
            clientPortsUsed.add(sport);

            serversPortsUsed.add(dport);
        } else if (destinationMac.equals(macAddress))
        {
            clientPortsUsed.add(dport);

            serversPortsUsed.add(sport);
        }
    }

    /**
     * Processes the UDP header of this packet
     */
    private static void processUDPheader()
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
    private static void processHTTPheader()
    {
        numberOfHTTPpackets++;

        if (http.isResponse())
        {
            processHTTPResponse();
            processHTTPServers();
        } else
        {
            processHttpHostnames();
            processHTTPRequestMethod();
            processHTTPUserAgents();
            processHTTPReferers();
        }
    }

    /**
     * Processes the HTTP request type of this packet
     */
    private static void processHTTPRequestMethod()
    {
        String requestMethod = http.fieldValue(Http.Request.RequestMethod);

        Integer count = httpRequestTypes.get(requestMethod);

        if (count == null)
        {
            httpRequestTypes.put(requestMethod, 1);
        } else
        {
            httpRequestTypes.put(requestMethod, count + 1);
        }

    }

    /**
     * Processes the HTTP response of this packet
     */
    private static void processHTTPResponse()
    {
        String httpResponseCode = http.fieldValue(Http.Response.ResponseCode);

        String httpResponseMsg = http.fieldValue(Http.Response.ResponseCodeMsg);

        String httpResponse = httpResponseCode + " " + httpResponseMsg;

        if (httpResponse != null)
        {
            Integer count = httpResponses.get(httpResponse);

            if (count == null)
            {
                httpResponses.put(httpResponse, 1);
            } else
            {
                httpResponses.put(httpResponse, count + 1);
            }
        }
    }

    /*
     * Processes the HTTP server of this packet
     */
    private static void processHTTPServers()
    {
        String httpServer = http.fieldValue(Http.Response.Server);

        if (httpServer != null)
        {
            String httpServerSanitised = Utils.sanitiseServerVersion(httpServer);

            Integer count = httpServers.get(httpServerSanitised);

            if (count == null)
            {
                httpServers.put(httpServerSanitised, 1);
            } else
            {
                httpServers.put(httpServerSanitised, count + 1);
            }
        }
    }

    /*
     * Processes the HTTP server of this packet
     */
    private static void processHTTPReferers()
    {
        String httpReferer = http.fieldValue(Http.Request.Referer);

        if (httpReferer != null)
        {
            String refererHostname = Utils.extractFQDNFromUri(httpReferer);

            Integer count = httpReferers.get(refererHostname);

            if (count == null)
            {
                httpReferers.put(refererHostname, 1);
            } else
            {
                httpReferers.put(refererHostname, count + 1);
            }
        }
    }


    /*
     * Processes the HTTP user agent of this packet
     */
    private static void processHTTPUserAgents()
    {
        String httpUserAgent = http.fieldValue(Http.Request.User_Agent);
        if (httpUserAgent != null)
        {
            Integer count = httpReferers.get(httpUserAgent);

            if (count == null)
            {
                httpUserAgents.put(httpUserAgent, 1);
            } else
            {
                httpUserAgents.put(httpUserAgent, count + 1);
            }
        }
    }

    /*
     * Processes the HTTP user agent of this packet
     */
    private static void processHttpHostnames()
    {
        String httpHost = http.fieldValue(Http.Request.Host);
        if (httpHost != null)
        {
            Integer count = httpHosts.get(httpHost);

            if (count == null)
            {
                httpHosts.put(httpHost, 1);
            } else
            {
                httpHosts.put(httpHost, count + 1);
            }
        }
    }

    /**
     * Processes images transferred over HTTP
     * Images transferred over SSL/TLS are not processed
     */
    private static void processImage()
    {
        numberOfImages++;

        String imageType = http.contentTypeEnum().toString();

        Integer count = imageTypes.get(imageType);

        if (count == null)
        {
            imageTypes.put(imageType, 1);
        } else
        {
            imageTypes.put(imageType, count + 1);
        }
    }


    /**
     * Adds the IP destination address to the Map of IP addresses visited
     *
     * @param sourceMac
     * @param destinationIP
     */
    private static void getDestinationAddress(String sourceMac, String destinationIP)
    {
        try
        {
            if (sourceMac.equals(macAddress))
            {
                ipAddressesVisited.put(destinationIP, "");
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Prints the ports that have been used
     *
     * @param portsUsed
     */
    private static void printPortsUsed(String machine, TreeSet<Integer> portsUsed)
    {
        writer.println();

        writer.println(machine + " ports utilised:");

        int i = 0;

        for (int port : portsUsed)
        {
            i++;

            writer.printf("%d  ", port);

            if (i % 18 == 0)
            {
                writer.println();
            }
        }
        writer.println();
    }

    /**
     * Prints the IP addresses that were visited along with their netnames
     *
     * @param ipAddressesVisited
     */
    private static void printIPaddressesVisited(HashMap<String, String> ipAddressesVisited) throws Exception
    {
        writer.println();

        writer.println("IP addresses visited:");

        for (Map.Entry entry : ipAddressesVisited.entrySet())
        {
            writer.printf("%-17s", entry.getKey());

            writer.print(": " + entry.getValue() + "\n");
        }

        writer.println();
    }

    /**
     * Resolves the IP addresses of the input Map and assigns the netname
     * as the value of each entry
     *
     * @param ipAddressesVisited
     * @throws Exception
     */
    private static void resolveIPaddresses(HashMap<String, String> ipAddressesVisited) throws Exception
    {
        for (Map.Entry entry : ipAddressesVisited.entrySet())
        {
            String ip = entry.getKey().toString();

            String netname = resolveNetname(ip);

            entry.setValue(netname);
        }
    }

    /**
     * Resolves the netname of the input IP address using the WhoIs Protocol
     * The first WhoIs server queried is whois.iana.org
     *
     * @param IPaddress the IP address to be resolved
     * @return
     * @throws Exception
     */
    private static String resolveNetname(String IPaddress) throws Exception
    {
        try
        {
            if (IPaddress.startsWith("192.168.") || (IPaddress.startsWith("10.")) || (IPaddress.startsWith("172.16")))
            {
                return "Local Address";
            }

            String netname = "";

            WhoisClient whoisClient = new WhoisClient();

            whoisClient.connect("whois.iana.org", 43);

            String queryResult = whoisClient.query(IPaddress);

            whoisClient.disconnect();

            String[] s = queryResult.split("\n");

            String serverToQuery = "";

            for (int i = 0; i < s.length; i++)
            {
                if (s[i].contains("whois:"))
                {
                    serverToQuery = s[i].substring(14);

                    break;
                }
            }

            String actualServer = serverToQuery;

            String tld = IPaddress.substring(IPaddress.lastIndexOf("")).trim().toLowerCase();

            whoisClient.connect(actualServer, 43);

            if (tld.equals("com"))
            {
                queryResult = whoisClient.query("domain " + IPaddress);
            } else
            {
                queryResult = whoisClient.query(IPaddress);
            }

            whoisClient.disconnect();

            String[] reply = queryResult.split("\n");

            for (int i = 0; i < reply.length; i++)
            {
                if (reply[i].startsWith("%"))
                {
                    continue;
                }
                if (reply[i].startsWith("NetName"))
                {
                    netname = reply[i].substring(16);
                    break;
                } else if (reply[i].startsWith("netname"))
                {
                    netname = reply[i].substring(16);
                    break;
                } else if (reply[i].startsWith("status"))
                {
                    netname = reply[i].substring(16);
                    break;
                } else if (reply[i].startsWith("Organization"))
                {
                    netname = reply[i].substring(16);
                    break;
                }
                if (reply[i].startsWith("OrgName"))
                {
                    netname = reply[i].substring(16);
                    break;
                }
            }

            if (!netname.equals(""))
            {
                return netname;
            } else
            {
                return "Not resolved";
            }

        }
        catch (IndexOutOfBoundsException e)
        {
            return "Error parsing WhoIs response";
        }
        catch (Exception e)
        {
            return "Not resolved";
        }
    }

    /**
     * Prints traffic statistics related to different protocols from different OSI layers
     * Protocols include: Ethernet, ARP, IP, TCP/UDP, SSL/TLS, DNS, HTTP
     */
    private static void printTrafficStatistics()
    {
        writer.printf("Report for " + pcapName + "\n\n");
        writer.printf("============================== Overview ==============================" + "\n");
        writer.printf("%-50s %s %8d \n", "Total number of packets in pcap", ": ", numberOfPackets);
        writer.printf("%-27s %-22s %s %8d %s %.2f %s \n", "Number of packets sent from", macAddress, ": ", numberOfPacketsSent, " ", ((float) numberOfPacketsSent / numberOfPackets) * 100, "%");
        writer.printf("%-27s %-22s %s %8d %s %.2f %s \n", "Number of packets sent to", macAddress, ": ", numberOfPacketsReceived, " ", ((float) numberOfPacketsReceived / numberOfPackets) * 100, "%");
        writer.printf("%-49s  %s %8d \n", "ARP packets", ": ", numberOfARPpackets);

        writer.printf("%-49s  %s %8d \n", "TCP packets", ": ", numberOfTcpPackets);
        writer.printf("%-49s  %s %8d \n", "SSL/TLS packets", ": ", numberOfSslTls);

        writer.printf("%-49s  %s %8d \n", "UDP packets", ": ", numberOfUdpPackets);
        writer.printf("%-49s  %s %8d \n", "DNS packets", ": ", numberOfDNS);
        writer.printf("%-49s  %s %8d \n", "HTTP packets", ": ", numberOfHTTPpackets);
    }

    /**
     * Prints the distribution among different TCP flags
     * TCP Flags include: [SYN], [SYN ACK], [ACK], [PSH ACK]
     * [FIN PSH ACK], [FIN ACK], [RST]
     */
    private static void printTCPflagsStatistics()
    {
        writer.println();
        writer.println("====================== TCP Flags distribution: ======================");
        writer.printf("%-50s %s %8d %7.2f %s \n", "SYN", ": ", numberOfSYN, ((float) numberOfSYN) / numberOfTcpPackets * 100, "%");
        writer.printf("%-50s %s %8d %7.2f %s \n", "SYN ACK", ": ", numberOfSYNACK, ((float) numberOfSYNACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-50s %s %8d %7.2f %s \n", "ACK", ": ", numberOfACK, ((float) numberOfACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-50s %s %8d %7.2f %s \n", "PSH ACK", ": ", numberOfPSHACK, ((float) numberOfPSHACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-50s %s %8d %7.2f %s \n", "FIN PSH ACK", ": ", numberOfFINPSHACK, ((float) numberOfFINPSHACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-50s %s %8d %7.2f %s \n", "FIN ACK", ": ", numberOfFINACK, ((float) numberOfFINACK) / numberOfTcpPackets * 100, "%");
        writer.printf("%-50s %s %8d %7.2f %s \n", "RST", ": ", numberOfRST, ((float) numberOfRST) / numberOfTcpPackets * 100, "%");
        writer.println();
    }


}

