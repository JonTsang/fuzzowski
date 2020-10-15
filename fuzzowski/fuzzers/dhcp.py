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
        s_byte(b'\x06', name='hardware_address_len', fuzzable=False)
        s_byte(b'\x00', name='hop', fuzzable=False)
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
        s_string('dhcpclient', name='servername', size=64)
        s_string('dhcpclient', name='boot_filename', size=128)

        #s_size("optiond", output_format="ascii", signed=True, fuzzable=True, name='Content-Length_size')

        s_static(b'\x63\x82\x53\x63', name='magic_cookie')


        #Host Name Option
        '''
        byte = os.urandom(1)
        n = int.from_bytes(byte, 'big')
        s_static(b'\x0c')
        s_static(os.urandom(1))
        s_string('a' * n, size=n)
        '''
        #Requested IP Address
        s_static(b'\x32')
        s_static(b'\x04')
        s_string('aaaa', size=0x04)

        #IP Address Lease Time
        s_static(b'\x33')
        s_static(b'\x04')
        s_string('aaaa', size=0x04)

        """
        #Option Overload
        s_static(b'\x34')
        s_static(b'\x01')
        s_group(b'\x01', values=[1, 2, 3])
        """

        #DHCP message type
        s_static(b'\x35')
        s_static(b'\x01')
        s_group(b'\x01',values=[1,2,3,4,5,7,8,9])

        #Server Identifier
        s_static(b'\x36')
        s_static(b'\x04')
        s_string('aaaa', size=0x04)

        #Parameter Request List
        s_static(b'\x37')
        s_byte(b'\x07')
        with s_block(name='request_list'):
            s_byte(b'\x01')
        s_repeat('request_list', name='repeat_reqestlist', min_reps=0, max_reps=7, step=7)

        #Message
        s_static(b'\x38')
        s_byte(b'\x38')
        s_string('aaaa')

        #Maximum DHCP Message Size
        s_static(b'\x39')
        s_byte(b'\xff')
        s_string('aaaa')

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
        s_random(b'\x01', min_length=1, max_length=1)
        s_string("aaa", fuzzable=True)

        #Client-identifier
        s_static(b'\x3d')
        s_static(b'\x00')
        s_string("aaa")

        #TFTP server name
        s_static(b'\x42')
        s_byte(b'\x00')
        s_string(b'\x00', )

        #Bootfile name
        s_static(b'\x43')
        s_byte(b'\x00')
        s_string(b'\x00')

        #Bootfile name
        s_static(b'\xff\x00\x00\x00')

        # --------------------------------------------------------------- #



    @staticmethod
    def boot_request(session: Session) -> None:
        session.connect(s_get('boot_request'))