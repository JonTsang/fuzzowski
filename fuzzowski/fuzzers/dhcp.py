from .ifuzzer import IFuzzer
from fuzzowski import Session
from fuzzowski.mutants.spike import *

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
        s_group(b'\x01', name='hareware_type', values=HARDWARE_TYPE)
        s_byte(b'\x06', name='hardware_address_len', fuzzable=True)
        s_byte(b'\x00', name='hop', fuzzable=True)
        s_random('0xdeadbeef', min_length=32, max_length=32, name='transaction_id', fuzzable=False)
        s_random('0x1234', min_length=16, max_length=16, name='seconds_elapsed', fuzzable=False)
        s_group(b'\x00\x00', name='flags', values=[b'\x80\x00', b'\x00\x00'])
        s_dword(0x00000000, name='client_ip', fuzzable=False)
        s_dword(0x00000000, name='your_client_ip', fuzzable=False)
        s_dword(0x00000000, name='next_server_ip', fuzzable=False)
        s_dword(0x00000000, name='rely_agent_ip', fuzzable=False)
        s_static(b'\x00\x0c\x29\x7f\xa9\x03', name='client_mac')
        s_static(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', name='client_mac_padding')
        s_string('dhcpclient', name='servername', size=64)
        s_string('dhcpclient', name='boot_filename', size=128)
        s_static(b'\x63\x82\x53\x63', name='magic_cookie')

        #Requested IP Address
        with s_block('request_ip'):
            s_static(b'\x32')
            s_static(b'\x04')
            s_string('aaaa', size=0x04)

        #IP Address Lease Time
        with s_block('ip_lease_time'):
            s_static(b'\x33')
            s_static(b'\x04')
            s_string('aaaa', size=0x04)

        #Option Overload
        with s_block('option_overload'):
            s_static(b'\x34')
            s_static(b'\x01')
            s_group(b'\x01', values=[1, 2, 3])

        #DHCP message type
        with s_block('dhcp_message_type'):
            s_static(b'\x35')
            s_static(b'\x01')
            s_group(b'\x01',values=[1,2,3,4,5,7,8,9])

        #Server Identifier
        with s_block('server_identifier'):
            s_static(b'\x36')
            s_static(b'\x04')
            s_string('aaaa', size=0x04)

        #Parameter Request List
        with s_block('request_list'):
            s_static(b'\x37')
            s_byte(b'\x00')
            s_string('aaaa', size=0x04)

        #Message
        with s_block('message'):
            s_static(b'\x38')
            s_static(b'\x00')
            s_string('aaaa', size=0x04)

        #Maximum DHCP Message Size
        with s_block('max_message_size'):
            s_static(b'\x39')
            s_static(b'\x02')
            s_string('aa', size=0x02)

        #Renewal (T1) Time Value
        with s_block('remewal_value'):
            s_static(b'\x3a')
            s_static(b'\x04')
            s_string('aaaa', size=0x04)

        #Rebinding (T2) Time Value
        with s_block('rebinding_value'):
            s_static(b'\x3b')
            s_static(b'\x04')
            s_string('aaaa', size=0x04)

        #Vendor class identifier
        with s_block('vendor_identifier'):
            s_static(b'\x3c')
            s_static(b'\x00')
            s_string("aaa")

        #Client-identifier
        with s_block('client-identifier'):
            s_static(b'\x3d')
            s_static(b'\x00')
            s_string("aaa")

        #TFTP server name
        with s_block('tftp_server_name'):
            s_static(b'\x42')
            s_byte(b'\x00')
            s_string(b'\x00', )

        #Bootfile name
        with s_block('bootfile_name'):
            s_static(b'\x43')
            s_byte(b'\x00')
            s_string(b'\x00')

        #Bootfile name
        with s_block('end'):
            s_static(b'\xff\x00\x00\x00')

        # --------------------------------------------------------------- #



    @staticmethod
    def boot_request(session: Session) -> None:
        session.connect(s_get('boot_request'))