package com.arisath.pcap;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by BDC on 2/1/2019.
 */
public class Utils
{

    static Properties loadPropertiesFile(String propertiesFileName)
    {
        try
        {
            InputStream input = null;

            input = PcapDissection.class.getClassLoader().getResourceAsStream(propertiesFileName);
            if (input == null)
            {
                System.out.println("Sorry, unable to find " + propertiesFileName);
                return null;
            }
            Properties prop = new Properties();
            prop.load(input);
            return prop;
        }
        catch (IOException exception)
        {
            System.out.println("Sorry, unable to find " + propertiesFileName);
        }
        return null;
    }

    static String sanitiseServerVersion(String fullServerName)
    {
        if (fullServerName.contains("nginx"))
        {
            return "nginx";
        }
        else if (fullServerName.contains("Apache"))
        {
            return "Apache";
        }
        else if (fullServerName.contains("Microsoft-IIS"))
        {
            return "Microsoft-IIS";
        }
        return fullServerName;
    }

    static String extractFqdnFromUri(String url)
    {
        try
        {
            URL aURL = new URL(url);

            return aURL.getHost();

        }
        catch (MalformedURLException malformedUrlException)
        {
            System.out.println("URL is malformed");
        }
        return null;
    }

    /**
     * Prints the distribution among different HTTP servers
     */
    static void printHttp(HashMap<String, Integer> httpServers)
    {
        int httpServersSum = 0;

        for (int value : httpServers.values())
        {
            httpServersSum += value;
        }

        PcapDissection.writer.println();

        PcapDissection.writer.println("====================== HTTP Servers distribution: ======================");

        List<Map.Entry<String, Integer>> sortedHTTPServers = httpServers.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                .collect(Collectors.toList());

        for (Map.Entry entry : sortedHTTPServers)
        {
            int value = (Integer) entry.getValue();

            PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(), ": ", value, ((float) value) / httpServersSum * 100, "%");
        }

        PcapDissection.writer.println();
    }

    /**
     * Prints the distribution among different HTTP responses
     */
    static void printHttpResponseStatistics(HashMap<String, Integer> httpResponses)
    {
        int httpResponsesSum = 0;

        for (int value : httpResponses.values())
        {
            httpResponsesSum += value;
        }

        PcapDissection.writer.println();

        PcapDissection.writer.println("====================== HTTP Responses distribution: =====================");

        List<Map.Entry<String, Integer>> sortedHTTPResponses = httpResponses.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toList());

        for (Map.Entry entry : sortedHTTPResponses)
        {
            int value = (Integer) entry.getValue();

            PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(), ": ", value, ((float) value) / httpResponsesSum * 100, "%");
        }

        PcapDissection.writer.println();
    }

    /**
     * Prints the distribution among different HTTP referers
     */
    static void printHttpReferersStatistics(HashMap<String, Integer> httpReferers)
    {
        PcapDissection.writer.println();

        if (httpReferers.size() > 0)
        {

            int httpReferersSum = 0;

            for (int value : httpReferers.values())
            {
                httpReferersSum += value;
            }


            PcapDissection.writer.println("====================== HTTP Referers distribution: =====================");

            List<Map.Entry<String, Integer>> sortedHttpReferers = httpReferers.entrySet()
                    .stream()
                    .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                    .collect(Collectors.toList());

            for (Map.Entry entry : sortedHttpReferers)
            {
                int value = (Integer) entry.getValue();

                PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(), ": ", value, ((float) value) / httpReferersSum * 100, "%");
            }
        }
        else
        {
            PcapDissection.writer.println("No HTTP Referers were identified");
        }
        PcapDissection.writer.println();
    }

    /**
     * Prints the most prevalent HTTP user agent
     */
    static void printHttpUserAgent(HashMap<String, Integer> httpUserAgents)
    {
        PcapDissection.writer.println();

        if (httpUserAgents.size() > 0)
        {

            List<Map.Entry<String, Integer>> sortedhttpReferers = httpUserAgents.entrySet()
                    .stream()
                    .sorted(Map.Entry.comparingByKey())
                    .collect(Collectors.toList());

            PcapDissection.writer.println("The most prevalent user agent is: " + sortedhttpReferers.get(0));

            PcapDissection.writer.println();
        }
        else
        {
            PcapDissection.writer.println("No user agent was identified");
        }
    }

    /**
     * Prints the most prevalent HTTP request types
     */
    static void printHttpRequestTypes(HashMap<String, Integer> httpRequestTypes)
    {
        PcapDissection.writer.println();

        if (httpRequestTypes.size() > 0)
        {
            PcapDissection.writer.println("==================== HTTP Request Types distribution: ===================");

            int httpRequestTypesSum = 0;

            for (int value : httpRequestTypes.values())
            {
                httpRequestTypesSum += value;
            }

            List<Map.Entry<String, Integer>> sortedHttpRequestTypes = httpRequestTypes.entrySet()
                    .stream()
                    .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                    .collect(Collectors.toList());

            for (Map.Entry entry : sortedHttpRequestTypes)
            {
                int value = (Integer) entry.getValue();

                PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(), ": ", value, ((float) value) / httpRequestTypesSum * 100, "%");
            }
            PcapDissection.writer.println();
        }
        else
        {
            PcapDissection.writer.println("No HTTP Requests were identified");
        }
    }


    /**
     * Prints the most prevalent HTTP user agent
     */
    static void printHttpHosts(HashMap<String, Integer> httpHosts)
    {
        PcapDissection.writer.println();

        if (httpHosts.size() > 0)
        {
            PcapDissection.writer.println("====================== HTTP Hosts distribution: ======================");

            int httpRequestTypesSum = 0;

            for (int value : httpHosts.values())
            {
                httpRequestTypesSum += value;
            }

            List<Map.Entry<String, Integer>> sortedHttpRequestTypes = httpHosts.entrySet()
                    .stream()
                    .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                    .collect(Collectors.toList());

            for (Map.Entry entry : sortedHttpRequestTypes)
            {
                int value = (Integer) entry.getValue();

                PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(), ": ", value, ((float) value) / httpRequestTypesSum * 100, "%");
            }
            PcapDissection.writer.println();
        }
        else
        {
            PcapDissection.writer.println("No HTTP hosts were identified");
        }
    }

    /**
     * Prints the ports that have been used
     *
     * @param portsUsed
     */
    protected static void printPortsUsed(String machine, TreeSet<Integer> portsUsed)
    {
        PcapDissection.writer.println();

        PcapDissection.writer.println(machine + " ports utilised:");

        int i = 0;

        for (int port : portsUsed)
        {
            i++;

            PcapDissection.writer.printf("%d  ", port);

            if (i % 18 == 0)
            {
                PcapDissection.writer.println();
            }
        }
        PcapDissection.writer.println();
    }


    /**
     * Prints the different SSL/TLS related messages
     */
    static void printSslTlsStatistics()
    {
        PcapDissection.writer.println();

        PcapDissection.writer.println("====================== SSL/TLS Statistics: ======================");

        PcapDissection.writer.printf("%-50s %s %8d  \n", "Client Hello", ": ", PcapDissection.numberOfClientHelloPackets);
        PcapDissection.writer.printf("%-50s %s %8d  \n", "Server Hello", ": ", PcapDissection.numberOfCServerHelloPackets);
        PcapDissection.writer.println();

    }





    /**
     * Prints the distributions among the different image types that
     * have been downloaded in the machine
     */
    static void printImageTypes()
    {
        PcapDissection.writer.printf("%s %d %s \n", "Found ", PcapDissection.numberOfImages, " images (images transferred over SSL/TLS not included):");

        for (Map.Entry entry : PcapDissection.imageTypes.entrySet())
        {
            PcapDissection.writer.printf("%-4s %s %d \n", entry.getKey(), " ", entry.getValue());
        }
    }

    /**
     * Grouping all other HTTP statistics printers
     */
    static void printHttpStatistics()
    {
        PcapDissection.writer.println();

        PcapDissection.writer.printf("\n%-28s %-10s %28s \n", "****************", "HTTP Statistics", "****************");

        printHttpRequestTypes(PcapDissection.httpRequestTypes);
        printHttpResponseStatistics(PcapDissection.httpResponses);
        printHttpHosts(PcapDissection.httpHosts);
        printHttpUserAgent(PcapDissection.httpUserAgents);
        printHttp(PcapDissection.httpServers);
        printHttpReferersStatistics(PcapDissection.httpReferers);
    }

    /**
     * Grouping all other TCP statistics printers
     */
    static void printTcpStatistics()
    {
        PcapDissection.writer.println();

        PcapDissection.writer.printf("\n%-28s %-10s %28s \n", "****************", "TCP Statistics", "****************");

        PcapDissection.printTcpFlagsStatistics();
        printSslTlsStatistics();
        printPortsUsed("Servers' ", PcapDissection.serversPortsUsed);
        printPortsUsed("Client's ", PcapDissection.clientPortsUsed);
    }

    static void createPdf()

    {
        try
        {
            Document document = new Document();
            PdfWriter.getInstance(document, new FileOutputStream("ExampleReport.pdf"));

            document.open();
            Font font = FontFactory.getFont(FontFactory.COURIER, 18, BaseColor.DARK_GRAY);
            Paragraph title = new Paragraph("Report for " + PcapDissection.pcapName, font);
            title.setAlignment(Element.ALIGN_CENTER);


            document.add(title);
            document.close();
        }
        catch (Exception e)
        {
           e.printStackTrace();
        }
    }


}
