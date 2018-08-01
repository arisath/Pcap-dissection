# Pcap-dissection
Pcap dissector implemented in Java using jnetpcap (http://jnetpcap.com/)

[![Generic badge](https://img.shields.io/badge/<CRYPTO>-<RSA>-<COLOR>.svg)](https://shields.io/)
[![star this repo](http://githubbadges.com/star.svg?user=arisath&repo=Pcap-dissection)](http://github.com/ddavison/github-badges)

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

