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
