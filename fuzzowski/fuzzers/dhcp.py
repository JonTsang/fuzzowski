import os
from .ifuzzer import IFuzzer
from fuzzowski import Session
from fuzzowski.mutants.spike import *
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

        s_initialize('boot_request')
        s_static(b'\x01', name='message_type')
        #s_group(b'\x01', name='hareware_type', values=HARDWARE_TYPE)
        s_static(b'\x01', name='hareware_type')
        s_byte(0x06, name='hardware_address_len', fuzzable=False)
        s_byte(0x00, name='hop', fuzzable=False)
        s_static(b'\xde\xad\xbe\xef', name='transaction_id')
        s_static(b'\x02\x34', name='seconds_elapsed')
        #s_random('\xde\xad\xbe\xef', min_length=4, max_length=4, name='transaction_id', fuzzable=True)
        #s_random('\x12\x34', min_length=2, max_length=2, name='seconds_elapsed', fuzzable=False)
        #s_group(b'\x00\x00', name='flags', values=[b'\x80\x00', b'\x00\x00'])
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
        #Host Name Option

        #Requested IP Address
        s_static(b'\x32')
        s_static(b'\x04')
        s_string('aaaa')

        #IP Address Lease Time
        s_static(b'\x33')
        s_static(b'\x04')
        s_string('aaaa')

        
        #Option Overload
        s_static(b'\x34')
        s_static(b'\x01')
        s_byte(b'\x01')

        #DHCP message type
        s_static(b'\x35')
        s_static(b'\x01')
        s_group(b'\x01',values=DHCP_MESSAGE_TYPE)

        
        #Server Identifier
        s_static(b'\x36')
        s_static(b'\x04')
        s_string('aaaa')


        #Parameter Request List
        s_static(b'\x37')
        s_byte(0xff)
        with s_block(name='request_list'):
            for i in range(1, 256):
                s_byte(i, fuzzable=True)

        #Message
        s_static(b'\x38')
        s_byte(0x4)
        s_string('aaaa')

        #Maximum DHCP Message Size
        s_static(b'\x39')
        s_byte(0x02)
        s_word(0xfefe)

        #Renewal (T1) Time Value
        s_static(b'\x3a')
        s_static(b'\x04')
        s_string('aaaa')

        #Rebinding (T2) Time Value
        s_static(b'\x3b')
        s_static(b'\x04')
        s_string('aaaa')

        #Vendor class identifier
        s_static(b'\x3c')
        s_static(b'\x10')
        s_string('aaaeaaaeaaaeaaae')

        #Client-identifier
        s_static(b'\x3d')
        s_static(b'\x07')
        s_static(b'\x01') # haredware type
        s_macaddr()

        #TFTP server name
        s_static(b'\x42')
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')

        #Bootfile name
        s_static(b'\x43')
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')

        #Bootfile name
        s_static(b'\x43')
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')

        #Bootfile name
        s_static(b'\x43')
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')


        #Bootfile name
        s_static(b'\x43')
        s_byte(0x10)
        s_string('aaaeaaaeaaaeaaae')

        #End
        s_static(b'\xff\x00\x00\x00')

        # --------------------------------------------------------------- #



    @staticmethod
    def boot_request(session: Session) -> None:
        session.connect(s_get('boot_request'))