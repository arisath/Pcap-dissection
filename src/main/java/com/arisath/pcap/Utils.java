package com.arisath.pcap;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

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

}
