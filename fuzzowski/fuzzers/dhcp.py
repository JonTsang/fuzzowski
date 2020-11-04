import os
from .ifuzzer import IFuzzer
from fuzzowski import Session
from fuzzowski.mutants.spike import *
from fuzzowski import ITargetConnection, IFuzzLogger, Session, Request, RegexResponse
from uuid import getnode

"""
reference:
    Dynamic Host Configuration Protocol (https://tools.ietf.org/html/rfc2131)
    DHCP Options and BOOTP Vendor Extensions (section 9)(https://tools.ietf.org/html/rfc2132)
"""

# Number of Hardware Type (rfc1700)
HARDWARE_TYPE = [
    '\x01' # Ethernet (10Mb)
    '\x02' # Experimental Ethernet (3Mb)
    '\x03' # Amateur Radio AX.25
    '\x04' # Proteon ProNET Token Ring
    '\x05' # Chaos
    '\x06' # IEEE 802 Networks
    '\x07' # ARCNET
    '\x08' # Hyperchannel
    '\x09' # Lanstar
    '\x10' # Autonet Short Address
    '\x11' # LocalTalk
    '\x12' # LocalNet (IBM PCNet or SYTEK LocalNET)
    '\x13' # Ultra link
    '\x14' # SMDS
    '\x15' # Frame Relay
    '\x16' # Asynchronous Transmission Mode (ATM)
    '\x17' # HDLC
    '\x18' # Fibre Channel
    '\x19' # Asynchronous Transmission Mode (ATM)
    '\x20' # Serial Line
    '\x21' # Asynchronous Transmission Mode (ATM)
]

DHCP_MESSAGE_TYPE = [
    '\x01' #DHCPDISCOVER
    '\x02' #DHCPOFFER
    '\x03' #DHCPREQUEST		
    '\x04' #DHCPDECLINE		
    '\x05' #DHCPACK			
    '\x06' #DHCPNAK			
    '\x07' #DHCPRELEASE		
    '\x08' #DHCPINFORM		
    '\x09' #DHCPLEASEQUERY		
    '\x0a' #DHCPLEASEUNASSIGNED	11
    '\x0b' #DHCPLEASEUNKNOWN	12
    '\x0c' #DHCPLEASEACTIVE		13
]


class DHCP(IFuzzer):
    """DHCP Fuzzer

    DHCP Fuzzer, incomplete
    """

    name = 'dhcp'

    @staticmethod
    def get_requests() -> List[callable]:
        """Get possible requests"""
        return [DHCP.boot_request]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:

        # ================================================================#
        # DHCP Discover                                                   #
        # ================================================================#

        s_initialize('discover')
        s_static(b'\x01', name='message_type')
        s_static(b'\x01', name='hareware_type')
        s_byte(0x06, name='hardware_address_len', fuzzable=False)
        s_byte(0x00, name='hop', fuzzable=False)
        s_dword(0xdeadbeef, name='transaction_id', fuzzable=False)
        s_word(0x0234, endian='>', name='seconds_elapsed', fuzzable=False)
        s_word(0x8000, endian='>', name='flags', fuzzable=False)
        s_dword(0x00000000, name='client_ip', fuzzable=False)
        s_dword(0x00000000, name='your_client_ip', fuzzable=False)
        s_dword(0x00000000, name='next_server_ip', fuzzable=False)
        s_dword(0x00000000, name='rely_agent_ip', fuzzable=False)
        s_macaddr(name='mac_address')
        s_static(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', name='mac_address_padding')
        s_string('servername', name='servername', size=64, fuzzable=False)
        s_string('boot_filename', name='boot_filename', size=128, fuzzable=False)
        
        #Host Name Option

        s_static(b'\x32') #Requested IP Address
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x33') #IP Address Lease Time
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x34') #Option Overload
        s_static(b'\x01')
        s_byte(b'\x01')

        s_static(b'\x35') #DHCP message type
        s_static(b'\x01')
        s_group(b'\x01',values=DHCP_MESSAGE_TYPE)

        s_static(b'\x36') #Server Identifier
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x37') #Parameter Request List
        s_byte(0xff)
        with s_block(name='request_list'):
            for i in range(1, 256):
                s_byte(i, fuzzable=True)

        s_static(b'\x38') #Message
        s_byte(0x4)
        s_string('aaaa')

        s_static(b'\x39') #Maximum DHCP Message Size
        s_byte(0x02)
        s_word(0xfefe)

        s_static(b'\x3a') #Renewal (T1) Time Value
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x3b') #Rebinding (T2) Time Value
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x3c') #Vendor class identifier
        s_static(b'\x10')
        s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x3d') #Client-identifier
        s_static(b'\x07')
        s_static(b'\x01') # haredware type
        s_macaddr()

        s_static(b'\x42') #TFTP server name
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x43') #Bootfile name
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')

        #End
        s_static(b'\xff\x00\x00\x00')

        # ================================================================#
        # DHCP Request                                                    #
        # ================================================================#

        s_initialize('request')
        s_static(b'\x01', name='message_type')
        s_static(b'\x01', name='hareware_type')
        s_byte(0x06, name='hardware_address_len', fuzzable=False)
        s_byte(0x00, name='hop', fuzzable=False)
        s_dword(0xdeadbeef, name='transaction_id', fuzzable=False)
        s_word(0x0234, endian='>', name='seconds_elapsed', fuzzable=False)
        s_word(0x0000, endian='>', name='flags', fuzzable=False)
        s_dword(0x00000000, name='client_ip', fuzzable=False)
        s_dword(0x00000000, name='your_client_ip', fuzzable=False)
        s_dword(0x00000000, name='next_server_ip', fuzzable=False)
        s_dword(0x00000000, name='rely_agent_ip', fuzzable=False)
        s_macaddr(name='mac_address')
        s_static(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', name='mac_address_padding')
        s_string('servername', name='servername', size=64, fuzzable=False)
        s_string('boot_filename', name='boot_filename', size=128, fuzzable=False)

        #s_size("optiond", output_format="ascii", signed=True, fuzzable=True, name='Content-Length_size')

        s_static(b'\x63\x82\x53\x63', name='magic_cookie')
        #Host Name Option

        s_static(b'\x32') #Requested IP Address
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x33') #IP Address Lease Time
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x34') #Option Overload
        s_static(b'\x01')
        s_byte(b'\x01')

        s_static(b'\x35') #DHCP message type
        s_static(b'\x01')
        s_group(b'\x01',values=DHCP_MESSAGE_TYPE)

        s_static(b'\x36') #Server Identifier
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x37') #Parameter Request List
        s_byte(0xff)
        with s_block(name='request_list'):
            for i in range(1, 256):
                s_byte(i, fuzzable=True)

        s_static(b'\x38') #Message
        s_byte(0x4)
        s_string('aaaa')

        s_static(b'\x39') #Maximum DHCP Message Size
        s_byte(0x02)
        s_word(0xfefe)

        s_static(b'\x3a') #Renewal (T1) Time Value
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x3b') #Rebinding (T2) Time Value
        s_static(b'\x04')
        s_string('aaaa')

        s_static(b'\x3c') #Vendor class identifier
        s_static(b'\x10')
        s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x3d') #Client-identifier
        s_static(b'\x07')
        s_static(b'\x01') # haredware type
        s_macaddr()

        s_static(b'\x42') #TFTP server name
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x43') #Bootfile name
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xff\x00\x00\x00') #End

        # ================================================================#
        # DHCP Release                                                    #
        # ================================================================#

        s_initialize('release')
        s_static(b'\x01', name='message_type')
        s_static(b'\x01', name='hareware_type')
        s_byte(0x06, name='hardware_address_len', fuzzable=False)
        s_byte(0x00, name='hop', fuzzable=False)
        s_static(b'\xde\xad\xbe\xef', name='transaction_id')
        s_static(b'\x02\x34', name='seconds_elapsed')
        s_static(b'\x00\x00', name='flags')
        s_dword(0x00000000, name='client_ip', fuzzable=False)
        s_dword(0x00000000, name='your_client_ip', fuzzable=False)
        s_dword(0x00000000, name='next_server_ip', fuzzable=False)
        s_dword(0x00000000, name='rely_agent_ip', fuzzable=False)
        s_macaddr(name='mac_address')
        s_static(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', name='mac_address_padding')
        s_string('servername', name='servername', size=64, fuzzable=False)
        s_string('boot_filename', name='boot_filename', size=128, fuzzable=False)

        #s_size("optiond", output_format="ascii", signed=True, fuzzable=True, name='Content-Length_size')

        s_static(b'\x63\x82\x53\x63', name='magic_cookie')
        
        #----------------Host Name Option---------------------
        s_static(b'\x02') #Time Offset
        s_size("2", fuzzable=False)
        with s_block("2"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x03') #Router
        s_size("3", fuzzable=False)
        with s_block("3"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x04') #Time Servers
        s_size("4", fuzzable=False)
        with s_block("4"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x05') #Name Servers
        s_size("5", fuzzable=False)
        with s_block("5"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x06') #DNS Servers
        s_size("6", fuzzable=False)
        with s_block("6"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x07') #Log Servers
        s_size("7", fuzzable=False)
        with s_block("7"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x08') #Cookie Servers
        s_size("8", fuzzable=False)
        with s_block("8"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x09') #LPR Servers
        s_size("9", fuzzable=False)
        with s_block("9"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x0a') #Impress Servers
        s_size("10", fuzzable=False)
        with s_block("10"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x0b') #RLP Servers
        s_size("11", fuzzable=False)
        with s_block("11"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x0c') #Host Name
        s_size("12", fuzzable=False)
        with s_block("12"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x0d') #Boot File Size
        s_size("13", fuzzable=False)
        with s_block("13"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x0e') #Merit Dump File
        s_size("14", fuzzable=False)
        with s_block("14"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x0f') #Domain Name
        s_size("15", fuzzable=False)
        with s_block("15"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x10') #Swap Server
        s_size("16", fuzzable=False)
        with s_block("16"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x11') #Root Path
        s_size("17", fuzzable=False)
        with s_block("17"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x12') #Extension File
        s_size("18", fuzzable=False)
        with s_block("18"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x13') #IP Layer Forwarding
        s_size("19", fuzzable=False)
        with s_block("19"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x14') #Src route enabler
        s_size("20", fuzzable=False)
        with s_block("20"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x15') #Policy Filter
        s_size("21", fuzzable=False)
        with s_block("21"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x16') #Maximum DG Reassembly Size
        s_size("22", fuzzable=False)
        with s_block("22"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x17') #Default IP TTL
        s_size("23", fuzzable=False)
        with s_block("23"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x18') #Path MTU Aging Timeout
        s_size("24", fuzzable=False)
        with s_block("24"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x19') #MTU Plateau
        s_size("25", fuzzable=False)
        with s_block("25"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x1a') #Interface MTU Size
        s_size("26", fuzzable=False)
        with s_block("26"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x1b') #All Subnets Are Local
        s_size("27", fuzzable=False)
        with s_block("27"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x1c') #Broadcast Address
        s_size("28", fuzzable=False)
        with s_block("28"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x1d') #Perform Mask Discovery
        s_size("29", fuzzable=False)
        with s_block("29"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x1e') #Provide Mask to Others
        s_size("30", fuzzable=False)
        with s_block("30"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x1f') #Perform Router Discovery
        s_size("31", fuzzable=False)
        with s_block("31"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x20') #Router Solicitation Address
        s_size("32", fuzzable=False)
        with s_block("32"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x21') #Static Routing Table
        s_size("33", fuzzable=False)
        with s_block("33"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x22') #Trailer Encapsulation
        s_size("34", fuzzable=False)
        with s_block("34"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x23') #ARP Cache Timeout
        s_size("35", fuzzable=False)
        with s_block("35"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x24') #Ethernet Encapsulation
        s_size("36", fuzzable=False)
        with s_block("36"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x25') #Default TCP Time to Live
        s_size("37", fuzzable=False)
        with s_block("37"):
            s_string('%n%n%n%n%n%n%n%n%n%n')
#===================================================
        s_static(b'\x26') #TCP Keepalive Interval
        s_size("38", fuzzable=False)
        with s_block("38"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x27') #TCP Keepalive Garbage
        s_size("39", fuzzable=False)
        with s_block("39"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x28') #NIS Domain Name
        s_size("40", fuzzable=False)
        with s_block("40"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x29') #NIS Server Addresses
        s_size("41", fuzzable=False)
        with s_block("41"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x2a') #NTP Servers Addresses
        s_size("42", fuzzable=False)
        with s_block("42"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x2b') #Vendor Specific Information
        s_size("43", fuzzable=False)
        with s_block("43"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x2c') #NetBIOS Name Server
        s_size("44", fuzzable=False)
        with s_block("44"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x2d') #NetBIOS Datagram Distribution
        s_size("45", fuzzable=False)
        with s_block("45"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x2e') #NetBIOS Node Type
        s_size("46", fuzzable=False)
        with s_block("46"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x2f') #NetBIOS Scope
        s_size("47", fuzzable=False)
        with s_block("47"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x30') #X Window Font Server
        s_size("48", fuzzable=False)
        with s_block("48"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x31') #X Window Display Manager
        s_size("49", fuzzable=False)
        with s_block("49"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x32') #Requested IP Address
        s_size("50", fuzzable=False)
        with s_block("50"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x33') #IP Address Lease Time
        s_size("51", fuzzable=False)
        with s_block("51"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x34') #Option Overload
        s_static(b'\x01')
        s_byte(b'\x01')

        s_static(b'\x35') #DHCP message type
        s_static(b'\x01')
        s_group(b'\x01',values=DHCP_MESSAGE_TYPE)

        s_static(b'\x36') #Server Identifier
        s_size("54", fuzzable=False)
        with s_block("54"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x37') #Parameter Request List
        s_byte(0xff)
        with s_block(name='request_list'):
            for i in range(1, 256):
                s_byte(i, fuzzable=True)

        s_static(b'\x38') #Message
        s_size("56", fuzzable=False)
        with s_block("56"):
            s_string('%n%n%n%n%n%n%n%n%n%n')

        s_static(b'\x39') #Maximum DHCP Message Size
        s_byte(0x02)
        s_word(0xfefe)

        s_static(b'\x3a') #Renewal (T1) Time Value
        s_size("58", fuzzable=False)
        with s_block("58"):
            s_string('aaaa')

        s_static(b'\x3b') #Rebinding (T2) Time Value
        s_size("59", fuzzable=False)
        with s_block("59"):
            s_string('aaaa')

        s_static(b'\x3c') #Vendor class identifier
        s_size("60", fuzzable=False)
        with s_block("60"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x3d') #Client-identifier
        s_static(b'\x07')
        s_static(b'\x01') # haredware type
        s_macaddr()

        s_static(b'\x3e') #Netware/IP Domain Name
        s_size("62", fuzzable=False)
        with s_block("62"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x3f') #Netware/IP sub Options
        s_size("63", fuzzable=False)
        with s_block("63"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x40') #NIS+ V3 Client Domain Name
        s_size("64", fuzzable=False)
        with s_block("64"):
            s_string('aaaeaaaeaaaeaaae')
        
        s_static(b'\x41') #NIS+ V3 Server Address
        s_size("65", fuzzable=False)
        with s_block("65"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x42') #TFTP server name
        s_size("66", fuzzable=False)
        with s_block("66"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x43') #Bootfile name
        s_size("67", fuzzable=False)
        with s_block("67"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x44') #Home Agent Addresses
        s_size("68", fuzzable=False)
        with s_block("68"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x45') #Simple Mail Server Addresses
        s_size("69", fuzzable=False)
        with s_block("69"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x46') #Post Office Server Addresses
        s_size("70", fuzzable=False)
        with s_block("70"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x47') #Network News Server Addresses
        s_size("71", fuzzable=False)
        with s_block("71"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x48') #WWW Server Addresses
        s_size("72", fuzzable=False)
        with s_block("72"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x49') #Finger Server Addresses
        s_size("73", fuzzable=False)
        with s_block("73"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x4a') #Chat Server Addresses
        s_size("74", fuzzable=False)
        with s_block("74"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x4b') #StreetTalk Server Addresses
        s_size("75", fuzzable=False)
        with s_block("75"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x4c') #StreetTalk Directory Assistance Addresses
        s_size("76", fuzzable=False)
        with s_block("76"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x4d') #User Class Information
        s_size("77", fuzzable=False)
        with s_block("77"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x4e') #SLP Directory Agent
        s_size("78", fuzzable=False)
        with s_block("78"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x4f') #SLP Service Scope
        s_size("79", fuzzable=False)
        with s_block("79"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x50') #Rapid Commit
        s_size("80", fuzzable=False)
        with s_block("80"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x51') #FQDN, Fully Qualified Domain Name
        s_size("81", fuzzable=False)
        with s_block("81"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x52') #Relay Agent Information
        s_size("82", fuzzable=False)
        with s_block("82"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x53') #Internet Storage Name Service
        s_size("83", fuzzable=False)
        with s_block("83"):
            s_string('aaaeaaaeaaaeaaae')
        
        s_static(b'\x55') #Novell Directory Servers
        s_size("85", fuzzable=False)
        with s_block("85"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x56') #Novell Directory Server Tree Name
        s_size("86", fuzzable=False)
        with s_block("86"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x57') #Novell Directory Server Context
        s_size("87", fuzzable=False)
        with s_block("87"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x58') #BCMCS Controller Domain Name List
        s_size("88", fuzzable=False)
        with s_block("88"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x59') #BCMCS Controller IPv4 Address List
        s_size("89", fuzzable=False)
        with s_block("89"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x5a') #Authentication
        s_size("90", fuzzable=False)
        with s_block("90"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x5d') #Client System
        s_size("93", fuzzable=False)
        with s_block("93"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x5e') #Client Network Device Interface
        s_size("94", fuzzable=False)
        with s_block("94"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x5f') #LDAP Use
        s_size("95", fuzzable=False)
        with s_block("95"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x61') #UUID/GUID Based Client Identifier
        s_size("97", fuzzable=False)
        with s_block("97"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x62') #Open Group’s User Authentication
        s_size("98", fuzzable=False)
        with s_block("98"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x6d') #Autonomous System Number
        s_size("109", fuzzable=False)
        with s_block("109"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x70') #NetInfo Parent Server Address
        s_size("112", fuzzable=False)
        with s_block("112"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x71') #NetInfo Parent Server Tag
        s_size("113", fuzzable=False)
        with s_block("113"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x72') #URL:
        s_size("114", fuzzable=False)
        with s_block("114"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x74') #Auto Configure
        s_size("116", fuzzable=False)
        with s_block("116"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x75') #Name Service Search
        s_size("117", fuzzable=False)
        with s_block("117"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x76') #Subnet Collection
        s_size("118", fuzzable=False)
        with s_block("118"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x77') #DNS Domain Search List
        s_size("119", fuzzable=False)
        with s_block("119"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x78') #SIP Servers DHCP Option
        s_size("120", fuzzable=False)
        with s_block("120"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x79') #Classless Static Route Option
        s_size("121", fuzzable=False)
        with s_block("121"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x7a') #CCC, CableLabs Client Configuration
        s_size("122", fuzzable=False)
        with s_block("122"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x7b') #GeoConf
        s_size("123", fuzzable=False)
        with s_block("123"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x7c') #Vendor-Identifying Vendor Class
        s_size("124", fuzzable=False)
        with s_block("124"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x7d') #Vendor Identifying Vendor Specific
        s_size("125", fuzzable=False)
        with s_block("125"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x80') #TFTP Server IP Address
        s_size("128", fuzzable=False)
        with s_block("128"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x81') #Call Server IP Address
        s_size("129", fuzzable=False)
        with s_block("129"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x82') #Discrimination String
        s_size("130", fuzzable=False)
        with s_block("130"):
            s_string('aaaeaaaeaaaeaaae')
        s_static(b'\x83') #Remote Statistics Server IP Address
        s_size("131", fuzzable=False)
        with s_block("131"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x84') #802.1Q VLAN ID
        s_size("132", fuzzable=False)
        with s_block("132"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x85') #802.1Q L2 Priority
        s_size("133", fuzzable=False)
        with s_block("133"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x86') #Diffserv Code Point
        s_size("134", fuzzable=False)
        with s_block("134"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x87') #HTTP Proxy For Phone Applications
        s_size("135", fuzzable=False)
        with s_block("135"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\x96') #TFTP Server Address, Etherboot, GRUB Config
        s_size("150", fuzzable=False)
        with s_block("150"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xaf') #Ether Boot
        s_size("175", fuzzable=False)
        with s_block("175"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xb0') #IP Telephone
        s_size("175", fuzzable=False)
        with s_block("175"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xb1') #Ether Boot PacketCable
        s_size("175", fuzzable=False)
        with s_block("175"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xd0') #pxelinux.magic (string) = 241.0.116.126
        s_size("208", fuzzable=False)
        with s_block("208"):
            s_string('241.0.116.126', fuzzable=False)

        s_static(b'\xdc') #pxelinux.configfile
        s_size("209", fuzzable=False)
        with s_block("209"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xdc') #pxelinux.pathprefix
        s_size("210", fuzzable=False)
        with s_block("210"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xdc') #pxelinux.reboottime
        s_size("211", fuzzable=False)
        with s_block("211"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xdc') #Subnet Allocation (Cisco Systems)
        s_size("220", fuzzable=False)
        with s_block("220"):
            s_string('aaaeaaaeaaaeaaae')


        s_static(b'\xdd') #Virtual Subnet Allocation
        s_size("221", fuzzable=False)
        with s_block("221"):
            s_string('aaaeaaaeaaaeaaae')

        # ------Private Use-Options-------------------------------------- #
        s_static(b'\xe0') 
        s_size("224", fuzzable=False)
        with s_block("224"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe1') 
        s_size("225", fuzzable=False)
        with s_block("225"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe2') 
        s_size("226", fuzzable=False)
        with s_block("226"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe3') 
        s_size("227", fuzzable=False)
        with s_block("227"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe4') 
        s_size("228", fuzzable=False)
        with s_block("228"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe5') 
        s_size("229", fuzzable=False)
        with s_block("229"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe6') 
        s_size("230", fuzzable=False)
        with s_block("230"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe7') 
        s_size("231", fuzzable=False)
        with s_block("231"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe8') 
        s_size("232", fuzzable=False)
        with s_block("232"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xe9') 
        s_size("233", fuzzable=False)
        with s_block("233"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xea') 
        s_size("234", fuzzable=False)
        with s_block("234"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xeb') 
        s_size("235", fuzzable=False)
        with s_block("235"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xec') 
        s_size("236", fuzzable=False)
        with s_block("236"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xed') 
        s_size("237", fuzzable=False)
        with s_block("237"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xee') 
        s_size("238", fuzzable=False)
        with s_block("238"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xef') 
        s_size("239", fuzzable=False)
        with s_block("239"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf0') 
        s_size("240", fuzzable=False)
        with s_block("240"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf1') 
        s_size("241", fuzzable=False)
        with s_block("241"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf2')
        s_size("242", fuzzable=False)
        with s_block("242"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf3') 
        s_size("243", fuzzable=False)
        with s_block("243"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf4')
        s_size("244", fuzzable=False) 
        with s_block("244"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf5') 
        s_size("245", fuzzable=False)
        with s_block("245"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf6') 
        s_size("246", fuzzable=False)
        with s_block("246"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf7') 
        s_size("247", fuzzable=False)
        with s_block("247"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf8') 
        s_size("248", fuzzable=False)
        with s_block("248"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xf9') 
        s_size("249", fuzzable=False)
        with s_block("249"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xfa') 
        s_size("250", fuzzable=False)
        with s_block("250"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xfb') 
        s_size("251", fuzzable=False)
        with s_block("251"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xfc') 
        s_size("252", fuzzable=False)
        with s_block("252"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xfd') 
        s_size("253", fuzzable=False)
        with s_block("253"):
            s_string('aaaeaaaeaaaeaaae')

        s_static(b'\xfe') 
        s_size("254", fuzzable=False)
        with s_block("254"):
            s_string('aaaeaaaeaaaeaaae')


        #End
        s_static(b'\xff\x00\x00\x00')

        # --------------------------------------------------------------- #





    @staticmethod
    def boot_request(session: Session) -> None:
        session.connect(s_get('discover'), s_get('request'), callback=DHCP.cb_set_request)


    @staticmethod
    def cb_set_request(target: ITargetConnection, logger: IFuzzLogger, session: Session, node: Request,
                     edge, original: bool, *args, **kwargs) -> bytes:
        """
        Callback used in send_uri that obtains the job-id and sets it in the send_uri node

        :param target: Target
        :param logger: Logger
        :param session: Fuzzing Session, most useful is session.last_recv
        :param node: Node to render next
        :param edge:
        :param args:
        :param kwargs:
        :return: the data of node.render() replacing the job-id for the one received in session.last_recv
        """
        logger.log_info('Callback cb_set_request')
        # target.close()
        # target.open()
        data = node.render(replace_node='your_client_ip', replace_value=client_ip, original=original)
        # logger.log_info(data)
        #return None
        return data
