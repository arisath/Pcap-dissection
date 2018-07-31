# Pcap-dissection
Pcap dissector implemented in Java using jnetpcap (http://jnetpcap.com/)

[![GitHub stars](https://img.shields.io/github/stars/Naereen/StrapDown.js.svg?style=social&label=Star&maxAge=2592000)](https://GitHub.com/arisath//Pcap-dissection)


## Metrics computed include:
* Number of packets sent/received
* HTTP packets
* Number of GET requests
* Number of POST requests
* Images downloaded
* DNS packets
* TCP packets
* Distribution of TCP flags
* SSL/TLS packets
* UDP packets
* Utilised ports
* IP addresses visited and their netnames

## Important 
The program requires importing the jnetpcap library as well as WinPcap version 4.0.1 (http://www.winpcap.org) or later for Windows OS and the libpcap RPM package for Linux/Debian. The WhoIs client is implemented using the apache.commons.net library (https://commons.apache.org/proper/commons-net/).

