from .ifuzzer import IFuzzer
from fuzzowski import Session
from fuzzowski.mutants.spike import *
from fuzzowski import ITargetConnection, IFuzzLogger, Session, Request, RegexResponse
from urllib.parse import quote_plus


login_path = "/webconsole/webpages/login.jsp"
controller = "/webconsole/Controller"
index = "/webconsole/webpages/index.jsp"
useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36"

class Sophos(IFuzzer):
    """
    Example module for fuzzing a CLI over Telnet (using the TelnetConnection Module)
    """

    name = 'sophos'

    def __init__(self):
        self.jsessionid = None
        self.csrftoken = None
        self.host = "192.168.123.100"
        self.port = 4444
        #self.auth(Session)

    def auth(self, session: Session):
        s_initialize("auth")
        s_static(b"POST /webconsole/Controller HTTP/1.1\r\n")
        s_static(b"Host: ")
        s_string(self.host, name='host_header_hostname', fuzzable=False)
        if self.port is not None:
            s_delim(b':' ,fuzzable=False)
            s_string(str(self.port).encode(), name='host_header_port', fuzzable=False)
        s_static(b"\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", fuzzable=False, name='Content-Length_size')
        s_static(b"\r\n")
        s_static(b"Accept: */*\r\n")
        s_static(b"X-Requested-With: XMLHttpRequest\r\n")
        s_static(b"User-Agent: ")
        s_string(b"Fuzzowski Agent", name='user_agent')
        s_static(b"\r\n")
        s_static(b'Connection: keep-alive\r\n')
        s_static(b"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n")
        s_static("Origi: https://")
        s_string(self.host, name='origi_host', fuzzable=False)
        if self.port is not None:
            s_delim(b':' ,fuzzable=False)
            s_string(str(self.port).encode(), name='host_header_port', fuzzable=False)
        s_static("\r\n")
        s_static(b"Referer: https://")
        s_string(self.host, fuzzable=False)
        s_delim(b":", fuzzable=False)
        s_string(str(self.port).encode(), fuzzable=False)
        s_static(b"/webconsole/webpages/login.jsp\r\n")
        s_static(b"\r\n")
        s_static(b"\r\n")
    
        with s_block("post_body"):
            json = """{"username":"admin","password":"Sophos172.16","languageid":"1","browser":"Chrome_84"}"""
            body = """mode=151&json=%s&__RequestType=ajax""" % quote_plus(json) 
            s_static(body)


        session.connect(s_get('auth'))
        session.connect(s_get('auth'), s_get('index'), callback=Sophos.cb_get_jsessionid)

        print("============%s=========" % self.jsessionid)

    @staticmethod
    def get_requests() -> List[callable]:
        return [Sophos.send_packet]

    @staticmethod
    def define_nodes(host: str = None, port: int = None, path: str = b'/', 
                    document_url: str = b'http://127.0.0.1/a.txt', 
                    username: str = b'admin', password: str = b'admin', 
                    *args, **kwargs) -> None:

        # ================================================================#
        # GET /webconsole/webpages/login.jsp                              #
        # ================================================================#

        s_initialize("login")
        s_static(b"GET ", name='http_method')
        s_string(login_path, name='path', fuzzable=False)
        s_static(b" HTTP/1.1\r\n")
        if host is not None:
            s_static(b"Host: ")
            s_string(host, name='host_header_hostname', fuzzable=False)
            s_delim(b':' ,fuzzable=False)
            s_string(str(port).encode(), name='host_header_port', fuzzable=False)
            s_static(b"\r\n")
        s_static(b"User-Agent: ")
        s_string(useragent, name='user_agent', fuzzable=False)
        s_static(b"\r\n")
        s_static(b"Accept: */*\r\n")
        s_static(b"\r\n")

        # ================================================================#
        # POST /webconsole/Controller HTTP/1.1                            #
        # ================================================================#
        s_initialize("auth")
        s_static(b"POST", name='http_method')
        s_static(b" ")
        s_string(controller, name='controller', fuzzable=False)
        s_static(b" HTTP/1.1\r\n")
        if host is not None:
            s_static(b"Host: ")
            s_string(host, name='host_header_hostname', fuzzable=False)
            s_delim(b':' ,fuzzable=False)
            s_string(str(port).encode(), name='host_header_port', fuzzable=False)
            s_static(b"\r\n")
        #s_static(b"Connection: close\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", fuzzable=False, name='Content-Length_size')
        s_static(b"\r\n")
        s_static(b"Accept: */*\r\n")
        s_static(b"X-Requested-With: XMLHttpRequest\r\n")
        s_static(b"User-Agent: ")
        s_string(b"Fuzzowski Agent", name='user_agent')
        s_static(b"\r\n")
        s_static(b'Connection: keep-alive\r\n')
        s_static(b"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n")
        if host is not None:
            origin_url = "https://" + host
            if port is not None:
                origin_url += ":" + str(port)
            s_static("Origi: ")
            s_static(origin_url)
            s_static("\r\n")
        s_static(b"Referer: https://")
        s_string(host, fuzzable=False)
        s_delim(b":", fuzzable=False)
        s_string(str(port).encode(), fuzzable=False)
        s_static(b"/webconsole/webpages/login.jsp\r\n")
        s_static(b"Cookie: JSESSIONID=")
        #s_string("141fj2q8x67ri141w55713wfpo3", name="jsessionid", fuzzable=False, size=27)
        s_string("000000000000000000000000000", name="jsessionid", fuzzable=False)
        s_static(b"\r\n")
        s_static(b"\r\n")
    
        with s_block("post_body"):
            json = """{"username":"admin","password":"Sophos172.16","languageid":"1","browser":"Chrome_84"}"""
            body = """mode=151&json=%s&__RequestType=ajax""" % quote_plus(json) 
            s_static(body)

        # ================================================================#
        # GET /webconsole/webpages/login.jsp                              #
        # ================================================================#
        s_initialize("index")
        s_static(b"GET", name='http_method')
        s_static(b" ")
        s_string(index, name='index', fuzzable=False)
        s_static(b" HTTP/1.1\r\n")
        if host is not None:
            s_static(b"Host: ")
            s_string(host, name='host_header_hostname', fuzzable=False)
            s_delim(b':' ,fuzzable=False)
            s_string(str(port).encode(), name='host_header_port', fuzzable=False)
            s_static(b"\r\n")
        #s_static(b"Connection: close\r\n")
        s_static(b"\r\n")
        s_static(b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n")
        s_static(b"User-Agent: ")
        s_string(b"Fuzzowski Agent", name='user_agent')
        s_static(b"\r\n")
        s_static(b"Referer: https://")
        s_string(host, fuzzable=False)
        s_delim(b":", fuzzable=False)
        s_string(str(port).encode(), fuzzable=False)
        s_static(b"/webconsole/webpages/login.jsp\r\n")
        s_static(b"Cookie: JSESSIONID=")
        s_string("000000000000000000000000000", name="jsessionid", fuzzable=False)
        s_static(b"\r\n")
        s_static(b"\r\n")
    
        with s_block("post_body"):
            json = """{"username":"admin","password":"Sophos172.16","languageid":"1","browser":"Chrome_84"}"""
            body = """mode=151&json=%s&__RequestType=ajax""" % quote_plus(json) 
            s_static(body)


        # ================================================================#
        # POST /webconsole/Controller HTTP/1.1   securitypolicy           #
        # ================================================================#
        s_initialize("securitypolicy")
        s_static(b"POST", name='http_method')
        s_static(b" ")
        s_string(controller, name='controller', fuzzable=False)
        s_static(b" HTTP/1.1\r\n")
        if host is not None:
            s_static(b"Host: ")
            s_string(host, name='host_header_hostname', fuzzable=False)
            s_delim(b':' ,fuzzable=False)
            s_string(str(port).encode(), name='host_header_port', fuzzable=False)
            s_static(b"\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", fuzzable=False, name='Content-Length_size')
        s_static(b"\r\n")
        s_static(b"Accept: */*\r\n")
        s_static(b"User-Agent: Fuzzowski Agent\r\n", name='user_agent')
        s_static(b"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n")
        if host is not None:
            origin_url = "https://" + host
            if port is not None:
                origin_url += ":" + str(port)
            s_static("Origi: ")
            s_static(origin_url)
            s_static("\r\n")
        s_static(b"Referer: https://")
        s_string(host, fuzzable=False)
        s_delim(b":", fuzzable=False)
        s_string(str(port).encode(), fuzzable=False)
        s_static(b"/webconsole/webpages/login.jsp\r\n")
        s_static(b"Cookie: JSESSIONID=")
        #s_string("141fj2q8x67ri141w55713wfpo3", name="jsessionid", fuzzable=False, size=27)
        s_string("000000000000000000000000000", name="jsessionid", fuzzable=False, size=27)
        s_static(b"\r\n")
        s_static(b"\r\n")
    
        with s_block("post_body"):
            s_static(b'Event=ADD&Entity=securitypolicy&mode=104&json=')
            json = """{"isenable":"1","policytype":"1","position":"-1","groupname_cat":"rulegroup","groupname":"Traffic to Internal Zones","ipfamily":"0","rulename":"asadaaa","description":"zbbb","firewallaction":"1","applysourcenat":"1","snatprofileid_cat":"snatprofileid","snatprofileid":"MASQ","overridenat":"0","gatewayid_cat":"Gateway","gatewayid":"0","bkpgatewayid_cat":"Gateway","bkpgatewayid":"0","dscpval":"-1","minpermittedhb":"3","dest_minpermittedhb":"3"}"""
            encode_json = quote_plus(json)
            s_string(encode_json)
            s_static(b'&__RequestType=ajax')

    # --------------------------------------------------------------- #

    @staticmethod
    def send_packet(session: Session) -> None:
        #Sophos.print_message()
        session.connect(s_get('auth'))
        session.connect(s_get('auth'), s_get('index'), callback=Sophos.cb_get_jsessionid)
        
        #session.connect(s_get('index'))
        #session.connect(s_get('index'), callback=Sophos.cb_get_csrftoken)

    @staticmethod
    def cb_get_jsessionid(target: ITargetConnection, logger: IFuzzLogger, session: Session, node: Request,
                     edge, original: bool, *args, **kwargs) -> bytes:
        """
        Callback used to get jsessionid 
        """
        logger.log_info('Callback cb_get_jsessionid')
        Sophos.jsessionid = session.last_recv[session.last_recv.find(b'JSESSIONID='):][11:37]
        logger.log_info('jsessionid found: %s' % Sophos.jsessionid)
        data = node.render(replace_node='jsessionid', replace_value=Sophos.jsessionid)
        return data

    @staticmethod
    def cb_get_csrftoken(target: ITargetConnection, logger: IFuzzLogger, session: Session, node: Request,
                     edge, original: bool, *args, **kwargs) -> bytes:
        """
        Callback used to get csrftoken
        """
        logger.log_info('Callback cb_get_csrftoken')
        Sophos.csrftoken = session.last_recv[session.last_recv.find(b'c$rFt0k3n = \''):][13:40]
        logger.log_info('csrftoken found: %s' % Sophos.csrftoken)
        data = node.render(replace_node='csrftoken', replace_value=Sophos.csrftoken)
        return data

    @staticmethod
    def cb_set_jsessionid(target: ITargetConnection, logger: IFuzzLogger, session: Session, node: Request,
                     edge, original: bool, *args, **kwargs) -> bytes:
        """
        Callback used in send_uri that obtains the job-id and sets it in the send_uri node
        """
        logger.log_info('Callback cb_set_jsessionid')
        data = node.render(replace_node='jsessionid', replace_value=Sophos.jsessionid)
        return data

    @staticmethod
    def print_message():
        print("hahahahahaha~")