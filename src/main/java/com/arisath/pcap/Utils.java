package com.arisath.pcap;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
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
        if(fullServerName.contains("nginx"))
        {
            return "nginx";
        }
        else if(fullServerName.contains("Apache"))
        {
            return "Apache";
        }
        else if(fullServerName.contains("Microsoft-IIS"))
        {
            return "Microsoft-IIS";
        }
        return  fullServerName;
    }

    static String extractFQDNFromUri(String url)
    {
        try
        {
            URL aURL = new URL(url);

            return aURL.getHost().toString();
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
    static void printHTTPServers(HashMap<String,Integer> httpServers)
    {
        int httpServersSum=0;

        for (int value : httpServers.values())
        {
            httpServersSum += value;
        }

        PcapDissection.writer.println();

        PcapDissection.writer.println("====================== HTTP Servers distribution: ======================");

        List<Map.Entry<String, Integer>> sortedHTTPServers =  httpServers.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                .collect(Collectors.toList());

        for (Map.Entry entry : sortedHTTPServers)
        {
            int value = (Integer) entry.getValue();

            PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(),": ",value,  ((float) value) / httpServersSum * 100, "%");
        }

        PcapDissection.writer.println();
    }

    /**
     * Prints the distribution among different HTTP responses
     */
    static void printHTTPResponseStatistics(HashMap<String,Integer> httpResponses)
    {
        int httpResponsesSum=0;

        for (int value : httpResponses.values())
        {
            httpResponsesSum += value;
        }

        PcapDissection.writer.println();

        PcapDissection.writer.println("====================== HTTP Responses distribution: ======================");

        List<Map.Entry<String, Integer>> sortedHTTPResponses =  httpResponses.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toList());

        for (Map.Entry entry : sortedHTTPResponses)
        {
            int value = (Integer) entry.getValue();

            PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(),": ",value,  ((float) value) / httpResponsesSum * 100, "%");
        }

        PcapDissection.writer.println();
    }

    /**
     * Prints the distribution among different HTTP referers
     */
    static void printHTTPReferersStatistics(HashMap<String,Integer> httpReferers)
    {
        int httpReferersSum=0;

        for (int value : httpReferers.values())
        {
            httpReferersSum += value;
        }

        PcapDissection.writer.println();

        PcapDissection.writer.println("====================== HTTP Referers distribution: ======================");

        List<Map.Entry<String, Integer>> sortedhttpReferers =  httpReferers.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                .collect(Collectors.toList());

        for (Map.Entry entry : sortedhttpReferers)
        {
            int value = (Integer) entry.getValue();

            PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(),": ",value,  ((float) value) / httpReferersSum * 100, "%");
        }

        PcapDissection.writer.println();
    }

    /**
     * Prints the most prevalent HTTP user agent
     */
    static void printHTTPUserAgent(HashMap<String,Integer> httpUserAgents)
    {
        PcapDissection.writer.println();

if (httpUserAgents.size()>0)
{

    List<Map.Entry<String, Integer>> sortedhttpReferers = httpUserAgents.entrySet()
            .stream()
            .sorted(Map.Entry.comparingByKey())
            .collect(Collectors.toList());

        PcapDissection.writer.println("The most prevalent user agent is: " + sortedhttpReferers.get(0));

    PcapDissection.writer.println();
}
        else {
    System.out.println("No user agent was identified");
        }
    }

    /**
     * Prints the most prevalent HTTP user agent
     */
    static void printHTTPRequestTypes(HashMap<String,Integer> httpRequestTypes)
    {
        PcapDissection.writer.println();

        if (httpRequestTypes.size()>0)
        {
            PcapDissection.writer.println("====================== HTTP Request Types distribution: ======================");

            int httpRequestTypesSum=0;

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

                PcapDissection.writer.printf("%-50s %s %8d %7.2f %s \n", entry.getKey(),": ",value,  ((float) value) / httpRequestTypesSum * 100, "%");
            }
            PcapDissection.writer.println();
        }
        else {
            System.out.println("No HTTP Requests were identified");
        }
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

}
