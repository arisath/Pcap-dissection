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

        PcapDissection.writer.println("HTTP Servers distribution:");

        List<Map.Entry<String, Integer>> sortedHTTPServers =  httpServers.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                .collect(Collectors.toList());

        for (Map.Entry entry : sortedHTTPServers)
        {
            int value = (Integer) entry.getValue();

            PcapDissection.writer.printf("%-55s %s %8d %5.2f %s \n", entry.getKey(),": ",value,  ((float) value) / httpServersSum * 100, "%");
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

        PcapDissection.writer.println("HTTP Responses distribution:");

        List<Map.Entry<String, Integer>> sortedHTTPResponses =  httpResponses.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toList());

        for (Map.Entry entry : sortedHTTPResponses)
        {
            int value = (Integer) entry.getValue();

            PcapDissection.writer.printf("%-12s %s %8d %5.2f %s \n", entry.getKey(),": ",value,  ((float) value) / httpResponsesSum * 100, "%");
        }

        PcapDissection.writer.println();
    }

}
