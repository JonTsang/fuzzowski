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

Option                    DHCPOFFER    DHCPACK            DHCPNAK
------                    ---------    -------            -------
Requested IP address      MUST NOT     MUST NOT           MUST NOT
IP address lease time     MUST         MUST (DHCPREQUEST) MUST NOT
                                       MUST NOT (DHCPINFORM)
Use 'file'/'sname' fields MAY          MAY                MUST NOT
DHCP message type         DHCPOFFER    DHCPACK            DHCPNAK
Parameter request list    MUST NOT     MUST NOT           MUST NOT
Message                   SHOULD       SHOULD             SHOULD
Client identifier         MUST NOT     MUST NOT           MAY
Vendor class identifier   MAY          MAY                MAY
Server identifier         MUST         MUST               MUST
Maximum message size      MUST NOT     MUST NOT           MUST NOT
All others                MAY          MAY                MUST NOT

           Table 3:  Fields and options used by DHCP servers

=====================================================================
=====================================================================

Option                     DHCPDISCOVER  DHCPREQUEST      DHCPDECLINE,
                           DHCPINFORM                     DHCPRELEASE
------                     ------------  -----------      -----------
Requested IP address       MAY           MUST (in         MUST
                           (DISCOVER)    SELECTING or     (DHCPDECLINE),
                           MUST NOT      INIT-REBOOT)     MUST NOT
                           (INFORM)      MUST NOT (in     (DHCPRELEASE)
                                         BOUND or
                                         RENEWING)
IP address lease time      MAY           MAY              MUST NOT
                           (DISCOVER)
                           MUST NOT
                           (INFORM)
Use 'file'/'sname' fields  MAY           MAY              MAY
DHCP message type          DHCPDISCOVER/ DHCPREQUEST      DHCPDECLINE/
                           DHCPINFORM                     DHCPRELEASE
Client identifier          MAY           MAY              MAY
Vendor class identifier    MAY           MAY              MUST NOT
Server identifier          MUST NOT      MUST (after      MUST
                                         SELECTING)
                                         MUST NOT (after
                                         INIT-REBOOT,
                                         BOUND, RENEWING
                                         or REBINDING)
Parameter request list     MAY           MAY              MUST NOT
Maximum message size       MAY           MAY              MUST NOT
Message                    SHOULD NOT    SHOULD NOT       SHOULD
Site-specific              MAY           MAY              MUST NOT
All others                 MAY           MAY              MUST NOT

             Table 5:  Fields and options used by DHCP clients

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

DHCP_MESSAGE_TYPE = {
    'DHCPDISCOVER':         '\x01',
    'DHCPOFFER':            '\x02',
    'DHCPREQUEST':          '\x03',
    'DHCPDECLINE':          '\x04',	
    'DHCPACK':              '\x05',		
    'DHCPNAK':              '\x06',		
    'DHCPRELEASE':          '\x07',		
    'DHCPINFORM':           '\x08',	
    'DHCPLEASEQUERY':       '\x09',	
    'DHCPLEASEUNASSIGNED':  '\x0a',
    'DHCPLEASEUNKNOWN':     '\x0b',
    'DHCPLEASEACTIVE':      '\x0c',
}

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
        DHCP.dhcp_header_node()
        DHCP.dhcp_options_node()
        '''
        s_initialize('request')
        DHCP.dhcp_header_node()
        DHCP.dhcp_options_node()

        s_initialize('inform')
        DHCP.dhcp_header_node()
        DHCP.dhcp_options_node()

        s_initialize('discover')
        DHCP.dhcp_header_node()
        DHCP.dhcp_options_node()

        s_initialize('discover')
        DHCP.dhcp_header_node()
        DHCP.dhcp_options_node()

        s_initialize('discover')
        DHCP.dhcp_header_node()
        DHCP.dhcp_options_node()
        '''
        #End
        s_static(b'\xff\x00\x00\x00')

    @staticmethod
    def dhcp_header_node(*args, **kwargs) -> None:
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
        s_static(b'\x63\x82\x53\x63', name='magic_cookie')

    @staticmethod
    def dhcp_options_node(*args, **kwargs) -> None:
        
        style_list = [
            # Always set to 1  
            (1, 23, 37, 46, 116, 156, 157,), 
            # Always set to 1 (list)
            (19, 20, 27, 29, 30, 31, 34, 36, 39),               
            # Always set to 2
            (13, 22, 26, 57, 66, 67,), 
            # Always set to 4
            (2, 16, 24, 28, 32, 35, 38, 51, 58, 59, 65, 68, 69, 70, 71,
             72, 73, 74, 75, 76, 91, 152, 153, 154, 155, 159),          
            # 4+ in multiples of 4
            (3, 4, 5, 6, 7, 8, 9, 10, 11, 41, 42, 44, 45, 48, 49, 85,
             92, 118, 138, 150, ),
            # 8+ in multiples of 8
            (21, 33),    
            # Variable length
            (12, 14, 15, 17, 18, 25, 40, 43, 47, 56, 60, 62, 64, 80,
             83, 86, 87, 88, 89, 90, 93, 94, 95, 96, 97, 98, 100, 101,
             112,113,114,128,129,130,131,132,133,134,135,136,137,139,
             140, 141,142, 143,144,145,145,151, 160,161,175,176,177,
             209,210,211, 222, 221)
        ]

        option_type_style = {
            style_list[0]: 0,
            style_list[1]: 1,
            style_list[2]: 2,
            style_list[3]: 3,
            style_list[4]: 4,
            style_list[5]: 5,
            style_list[6]: 6,
        }


        '''
        #50 Requested IP Address
        s_static(b'\x32') #Requested IP Address
        s_size("50", length=1, fuzzable=False)
        with s_block("50"):
            s_string('%n%n', size=4, fuzzable=True)
        '''
        
        s_static(b'\x17')
        s_static(b'\x01')
        s_byte(0x01)

        #52 Option Overload
        '''
        s_static(b'\x34')
        s_static(b'\x01')
        s_byte(b'\x01')
        '''
        #53 DHCP message type
        s_static(b'\x35')
        s_static(b'\x01')
        s_group(b'\x01',values=DHCP_MESSAGE_TYPE['DHCPDISCOVER'])

        '''
        #54 Server Identifier
        if not s_get('discover'):
            DHCP.dhcp_option_builder(name='54', option_type=b'\x36', style=3)
        '''
        '''
        #55 Parameter Request List
        s_static(b'\x37')
        s_byte(0xff)
        with s_block(name='request_list'):
            for i in range(1, 256):
                s_byte(i, fuzzable=True)

        #61 Client-identifier
        s_static(b'\x3d') 
        s_static(b'\x07')
        s_static(b'\x01') # haredware type
        s_macaddr()
        '''

        #82 Relay Agent Information
        s_static(b'\x52')
        s_size("82", length=1, fuzzable=False)
        with s_block("82"):
            for i in range(1, 3):
                DHCP.dhcp_option_builder(name='sub'+str(i), option_type=i, style=5)

            s_static(b'\x09')
            s_size("82_sub_09", length=1, fuzzable=False)
            with s_block("82_sub_09"):
                s_dword(0x12b0, endian='>', fuzzable=False)
                s_string("aaaaaaa")

 
        '''
        #78 SLP Directory Agent Option
        # Length:
        # Value:
        # IP Address:
        # IP Address:
        # ...
        s_static(b'\x4e')
        s_size("78", fuzzable=False)
        with s_block("78"):
            s_string('aaaeaaaeaaaeaaae')

        #79 SLP Service Scope Option
        s_static(b'\x4f')
        s_size("79", fuzzable=False)
        with s_block("79"):
            s_string('aaaeaaaeaaaeaaae')

        #81 Client Fully Qualified Domain Name
        s_static(b'\x51')
        s_size("81", fuzzable=False)
        with s_block("81"):
            s_string('aaaeaaaeaaaeaaae')

        #82 Relay Agent Information
        s_static(b'\x52')
        s_size("82", fuzzable=False)
        with s_block("82"):
            s_string('aaaeaaaeaaaeaaae')

        #99 Civic Addresses Configuration
        s_static(b'\x63')
        s_size("99", fuzzable=False)
        with s_block("99"):
            s_string('aaaeaaaeaaaeaaae')

        #117 Name Service Search
        s_static(b'\x75')
        s_size("117", fuzzable=False)
        with s_block("117"):
            s_string('aaaeaaaeaaaeaaae')

        #119 DNS Domain Search List
        s_static(b'\x77')
        s_size("119", fuzzable=False)
        with s_block("119"):
            s_string('aaaeaaaeaaaeaaae')

        #120 SIP Servers DHCP Option
        s_static(b'\x78')
        s_size("120", fuzzable=False)
        with s_block("120"):
            s_string('aaaeaaaeaaaeaaae')

        #121 Classless Static Route Option
        s_static(b'\x79') 
        s_size("121", fuzzable=False)
        with s_block("121"):
            s_string('aaaeaaaeaaaeaaae')
        
        #122 CCC, CableLabs Client Configuration
        s_static(b'\x7a')
        s_size("122", fuzzable=False)
        with s_block("122"):
            s_string('aaaeaaaeaaaeaaae')

        #123 GeoConf
        s_static(b'\x7b')
        s_size("123", fuzzable=False)
        with s_block("123"):
            s_string('aaaeaaaeaaaeaaae')

        #124 Vendor-Identifying Vendor Class
        s_static(b'\x7c')
        s_size("124", fuzzable=False)
        with s_block("124"):
            s_string('aaaeaaaeaaaeaaae')

        #125 Vendor Identifying Vendor Specific
        s_static(b'\x7d')
        s_size("125", fuzzable=False)
        with s_block("125"):
            s_string('aaaeaaaeaaaeaaae')

        #146 RDNSS Selection
        s_static(b'\x92') 
        s_size("125", fuzzable=False)
        with s_block("125"):
            s_string('aaaeaaaeaaaeaaae')
       
        #208 pxelinux.magic (string) = 241.0.116.126
        s_static(b'\xd0')
        s_size("208", fuzzable=False)
        with s_block("208"):
            s_string('241.0.116.126', fuzzable=False)

        #209 pxelinux.configfile
        s_static(b'\xd1') 
        s_size("209", fuzzable=False)
        with s_block("209"):
            s_string('aaaeaaaeaaaeaaae')

        #210 pxelinux.pathprefix
        s_static(b'\xd2')
        s_size("210", fuzzable=False)
        with s_block("210"):
            s_string('aaaeaaaeaaaeaaae')

        #211 pxelinux.reboottime
        s_static(b'\xd3')
        s_size("211", fuzzable=False)
        with s_block("211"):
            s_string('aaaeaaaeaaaeaaae')

        #220 Subnet Allocation (Cisco Systems)
        s_static(b'\xdc')
        s_size("220", fuzzable=False)
        with s_block("220"):
            s_string('aaaeaaaeaaaeaaae')

        #221 Virtual Subnet Allocation
        s_static(b'\xdd')
        s_size("221", fuzzable=False)
        with s_block("221"):
            s_string('aaaeaaaeaaaeaaae')
        '''
        '''
        # ----------Default defined options----------------------------- #
        for i in range(2, 222):
            for style in style_list:
                if i in style:
                    DHCP.dhcp_option_builder(name=str(i), option_type=i, style=option_type_style[style])


        # ------Private Use-Options----224~254-------------------------- #
        for i in range(224, 255):
            DHCP.dhcp_option_builder(name=str(i), option_type=i, style=7)
        '''


    @staticmethod
    def dhcp_option_builder(name: str, option_type: int, style: int, 
                            value: Union[str, bytes, list, int] = None) -> None:
        '''
        Generate DHCP Option

        Args:
            name: Specifying a name gives you option
            option_type: DHCP Options types
            sytle:  DHCP Option style

                0 -> Length: Always set to 1
                1 -> Length: Always set to 1 (0x00 or 0x01)
                2 -> Length: Always set to 2
                3 -> Length: Always set to 4
                4 -> Length: 4+ in multiples of 4
                5 -> Length: Always set to 8
                6 -> Length: 8+ in multiples of 8
                7 -> Length: 1+
        '''

        switch = {
            0: lambda: s_byte(b'a', fuzzable=True),
            1: lambda: s_group(b'\x00', values=['\x00', '\x01']),
            2: lambda: s_word(0xffff, endian='>', fuzzable=False),
            3: lambda: s_string('%n%n', size=4, fuzzable=True),
            4: lambda: s_string('%n%n'*4, size=16, fuzzable=True),
            5: lambda: s_string('%n%n'*2, size=8, fuzzable=True),
            6: lambda: s_string('%n%n'*8, size=32, fuzzable=True),
            7: lambda: s_string('%n%n'*32),
        }

        s_static(option_type.to_bytes(1, 'big'))
        s_size(name, length=1, fuzzable=False)
        with s_block(name):
            switch.get(int(style))()

    @staticmethod
    def boot_request(session: Session) -> None:
        session.connect(s_get('discover'))
        #session.connect(s_get('discover'), s_get('request'), callback=DHCP.cb_set_request)


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
