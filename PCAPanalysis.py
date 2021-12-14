# Script Purpose: Python PCAP Analysis
# Script Version: 1.0 
# Script Author:  Tala Vahedi

# Script Revision History:
# Version 1.0 Oct 20, 2021, Python 3.x

# Python Standard Library Module Imports
import sys               # System specifics
import platform          # Platform specifics
import os                # Operating/Filesystem Module
import pickle            # Object serialization
import time              # Basic Time Module
import re                # regular expression library
from binascii import unhexlify

# 3rd Party Libraries
from prettytable import PrettyTable   # pip install prettytable
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network   import ip
from pcapfile.protocols.transport import tcp
from pcapfile.protocols.transport import udp


# Script Constants
SCRIPT_NAME    = "Script: Python PCAP Analysis"
SCRIPT_VERSION = "Version 1.0"
SCRIPT_AUTHOR  = "Author: Tala Vahedi"
DEBUG   = True

# Script Local Functions
class ETH:
    '''LOOKUP ETH TYPE'''
    def __init__(self):
    
        self.ethTypes = {}
        
        self.ethTypes[2048]   = "IPv4"
        self.ethTypes[2054]   = "ARP"
        self.ethTypes[34525]  = "IPv6"
            
    def lookup(self, ethType):
        
        try:
            result = self.ethTypes[ethType]
        except:
            result = "not-supported"
            
        return result

# MAC Address Lookup Class
class MAC:
    ''' OUI TRANSLATION MAC TO MFG'''
    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('oui.pickle', 'rb') as pickleFile:
            self.macDict = pickle.load(pickleFile)
            
    def lookup(self, macAddress):
        try:
            result = self.macDict[macAddress]
            cc  = result[0]
            oui = result[1]
            return cc+","+oui
        except:
            return "Unknown"
        
# Transport Lookup Class
class TRANSPORT:
    ''' PROTOCOL TO NAME LOOKUP'''
    def __init__(self):
        
        # Open the transport protocol Address OUI Dictionary
        with open('protocol.pickle', 'rb') as pickleFile:
            self.proDict = pickle.load(pickleFile)
    def lookup(self, protocol):
        try:
            result = self.proDict[protocol][0]
            return result
        except:
            return ["unknown", "unknown", "unknown"]

#PORTS Lookup Class
class PORTS:
    ''' PORT NUMBER TO PORT NAME LOOKUP'''
    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('ports.pickle', 'rb') as pickleFile:
            self.portDict = pickle.load(pickleFile)
            
    def lookup(self, port, portType):
        try:
            result = self.portDict[(port,portType)]
            return result
        except:
            return "EPH"

# IP Observations update class
class IPObservations:
    # Constructor
    def __init__(self):
        #Attributes of the Object
        self.Dictionary = {}            # Dictionary to Hold IP Observations
        self.portObservations = {}
        
    # Method to Add an observation
    def AddOb(self, key, value, hr):
        # Check to see if key is already in the dictionary
        try:
            curValue = self.Dictionary[key]
            hourList = curValue[0]
            hourList[hr] += 1
        
            # Update the value associated with this key
            self.Dictionary[key] = [hourList, value]
    
        except:
            # if the key doesn't yet exist
            # Create one
            hourList = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            hourList[hr] += 1
            self.Dictionary[key] = [hourList, value]

    def AddPortOb(self, key, desc):
        # Check to see if key is already in the dictionary
        if key not in self.portObservations:
            self.portObservations[key] = desc
    
    def PrintIPObservations(self):
        #tbl = PrettyTable(['SRC-IP', 'DST-IP', 'SRC-MAC', 'DST-MAC', 'SRC-MFG', 'DST-MFG', 'SRC-PORT', 'DST-PORT', 'TTL', 'HR-0', 'HR-1','HR-2','HR-3','HR-4','HR-5','HR-6','HR-7','HR-8','HR-9','HR-10','HR-11','HR-12','HR-13','HR-14','HR-15','HR-16','HR-17','HR-18','HR-19','HR-20','HR-21','HR-22','HR-23'])
        '''
                    key   = (srcMAC, dstMAC, srcPort, dstPort, "TCP")
                    value = [srcIP, dstIP, srcPortDesc, dstPortDesc, protocol, srcCC+","+srcOU, dstCC+","+dstOU, ttl]

        '''
        kx = {
            'sMac': 0,
            'dMac': 1,            
            'sPrt': 2,
            'dPrt': 3,
            'prot': 4
            }
            
        vx = {
            'sIP': 0,
            'dIP': 1,
            'sPrtDesc': 2,            
            'dPrtDesc': 3,
            'sMFG': 4,
            'dMFG': 5,
            'ttl':  6
            }               
        
        tbl = PrettyTable(['SRC-IP', 'DST-IP', 'PROTOCOL', 'SRC-MAC', 'DST-MAC', 'SRC-MFG', 'DST-MFG', 'SRC-PORT', 'SRC-PORT-NAME', 'DST-PORT', 'DST-PORT-NAME', 'TTL', 'HR-00','HR-01','HR-02','HR-03','HR-04','HR-05','HR-06','HR-07','HR-08','HR-09','HR-10','HR-11','HR-12','HR-13','HR-14','HR-15','HR-16','HR-17','HR-18','HR-19','HR-20','HR-21','HR-22','HR-23'])
        print("\nIP Observations")
        
        for k, v in self.Dictionary.items():
            row = []
            hourList = v[0]
            ob  = v[1]
            row.append(ob[vx['sIP']])
            row.append(ob[vx['dIP']])
            row.append(k[kx['prot']])
            row.append(k[kx['sMac']])
            row.append(k[kx['dMac']])
            row.append(ob[vx['sMFG']])
            row.append(ob[vx['dMFG']])
            row.append(k[kx['sPrt']])
            row.append(k[kx['dPrt']])
            row.append(ob[vx['sPrtDesc']])
            row.append(ob[vx['dPrtDesc']])
            row.append(ob[vx['ttl']])
            
            for eachHr in hourList:
                row.append(eachHr)
            
            tbl.add_row(row)
            
        tbl.align = 'l'
        print(tbl.get_string(sortby="PROTOCOL"))
            
    def PrintPortObservations(self):
        tbl = PrettyTable(["IP", "PORT", "PORT-DESCRIPTION"])
        print("\nPORT Observations")
        for key, value in self.portObservations.items():
            tbl.add_row([key[0], key[1], value])
        
        tbl.align='l'
        print(tbl.get_string(sortby="IP"))
        
    # Destructor Delete the Object
    def __del__(self):
        if DEBUG:
            print ("Closed")

# End IPObservationClass ====================================

if __name__ == '__main__':
        print("PCAP PROCESSOR v 1.0 OCTOBER 2021")
        
        # Create Lookup Objects
        macOBJ  = MAC()
        traOBJ  = TRANSPORT()
        portOBJ = PORTS()
        ethOBJ  = ETH()     
        ipOBJ   = IPObservations()
        
        ''' Attempt to open a PCAP '''
        while True:
            targetPCAP = input("Please Enter A Target PCAP File: ")
            if not os.path.isfile(targetPCAP):
                print("Invalid File: Please enter valid path\n")
                continue      
            try:
                pcapCapture = open(targetPCAP, 'rb')
                capture = savefile.load_savefile(pcapCapture, layers=0, verbose=False)
                # print(capture)
                print("PCAP File Is Ready for Processing...")
                break
            except:
                # Unable to ingest pcap       
                print("!! Unsupported PCAP File Format !! ")
                continue

        totPackets      = 0
        pktCnt          = 0

        # Now process each packet
        for pkt in capture.packets:
            pktCnt += 1
            ''' extract the hour the packet was captured '''
            pktHR = time.strftime('%H', time.localtime(pkt.timestamp))
            hr = int(pktHR)
            
            ''' Get the raw ethernet frame '''
            rawEthernetFame = ethernet.Ethernet(pkt.raw())
                
            ''' ---- Extract the source and destination mac address ---- '''
            srcMAC = rawEthernetFame.src.decode("utf-8")
            dstMAC = rawEthernetFame.dst.decode("utf-8")
            srcOUI = srcMAC[0:8].replace(":","").upper()
            dstOUI = dstMAC[0:8].replace(":","").upper()
            srcMFG = macOBJ.lookup(srcOUI)
            dstMFG = macOBJ.lookup(dstOUI)

            ''' Lookup the Frame Type '''
            frameType = rawEthernetFame.type
            pktFrameType = ethOBJ.lookup(frameType)
            
            ''' Process any IPv4 Frames '''
            if pktFrameType == "IPv4":
                ''' Extract the payload '''
                ipPacket = ip.IP(unhexlify(rawEthernetFame.payload))
                    
                ''' Extract the source and destination ip addresses '''
                srcIP = ipPacket.src.decode("utf-8")
                dstIP = ipPacket.dst.decode("utf-8")

                ''' Extract the protocol in use '''
                protocol = ipPacket.p
                
                ''' Lookup the transport protocol in use '''
                transport = traOBJ.lookup(str(protocol))

                ''' extract the ttl '''
                ttl = ipPacket.ttl
                
                if transport == "TCP":
                    # looking up tcp payload
                    tcpPacket = tcp.TCP(unhexlify(rawEthernetFame.payload))
                    
                    # extracting source and destination ports
                    srcPort = tcpPacket.src_port
                    dstPort = tcpPacket.dst_port
                    
                    # Lookup Port Description, if not found assume Ephemeral 
                    srcPortDesc = portOBJ.lookup(str(srcPort), transport)
                    dstPortDesc = portOBJ.lookup(str(dstPort), transport)
                    
                    # Add a new IP observation and the hour
                    key   = (srcMAC, dstMAC, srcPort, dstPort, transport)
                    value = [srcIP, dstIP, srcPort, dstPort, srcMFG, dstMFG, ttl]
                    ipOBJ.AddOb(key, value, hr)

                    # Post them to PortObject Dictionary
                    key = (srcIP, srcPort)
                    desc = srcPortDesc
                    ipOBJ.AddPortOb(key, desc)
                        
                elif transport == "UDP":
                    # the pypcapfile library provides a udp object to extract the
                    # UDP packet contents
                    udpPacket = udp.UDP(unhexlify(ipPacket.payload))
                    
                    # As with TCP, we can extract the source and destination port numbers
                    srcPort = udpPacket.src_port
                    dstPort = udpPacket.dst_port
                    
                    # Lookup Port Description, if not found assume Ephemeral 
                    srcPortDesc = portOBJ.lookup(str(srcPort), transport)
                    dstPortDesc = portOBJ.lookup(str(dstPort), transport)
                        
                     # Add a new IP observation and the hour
                    key   = (srcMAC, dstMAC, srcPort, dstPort, transport)
                    value = [srcIP, dstIP, srcPort, dstPort, srcMFG, dstMFG, ttl]
                    ipOBJ.AddOb(key, value, hr)

                    # Post them to PortObject Dictionary
                    key = (srcIP, srcPort)
                    desc = srcPortDesc
                    ipOBJ.AddPortOb(key, desc)
                  
                elif transport == "ICMP":
                    # Since the ICMP packet does not contain src/dst ports
                    # we have all the information we need
                    # src/dst IP and the type ICMP thus we can simply add the
                    # the observation, marking the src/dst port as blank
                    # and the packet type as ICMP
                    # Add a new IP observation and the hour
                    
                    key   = (srcMAC, dstMAC, "", "", "ICMP")
                    value = [srcIP, dstIP, "", "", srcMFG, dstMFG, ttl]
                    ipOBJ.AddOb(key, value, hr)

                    
            elif pktFrameType == "ARP":
                # Add a new IP observation and the hour
                key   = (srcMAC, dstMAC, "", "", "")
                value = ["", "", "", "", srcMFG, dstMFG, ""]
                ipOBJ.AddOb(key, value, hr)

            else:
                continue
        
        # print the ip and port observations
        ipOBJ.PrintIPObservations()
        ipOBJ.PrintPortObservations()
        
        print("\n\nScript End")