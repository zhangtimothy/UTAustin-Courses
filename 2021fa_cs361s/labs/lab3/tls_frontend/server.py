import asyncio, time, struct
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac # avoid name collision
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
from scapy.all import *
from scapy.layers.tls.keyexchange import _TLSSignature
from scapy.layers.tls.handshake import _TLSCKExchKeysField
from datetime import datetime, timedelta
from urllib.parse import urlparse

from .debug import Debug
from .tls_session import TLSSession
from .tls_visibility import TLS_Visibility

load_layer("tls")


### Utils ###
### End Utils ###
        
class TLSHTTPProxy(asyncio.Protocol):
    def __init__(self, root_cert, root_key):
        super().__init__()
        self.root_cert = root_cert
        self.root_key  = root_key
        self.backlog = b""
        
    def generate_proxy_crypto(self, host):
        """ 
        STUDENT TODO 
        For the given host, you need to generate a certificate
        on the fly. The common name must have the host name.
        The issuer must be the subject of the root cert. The
        certificate must also be signed by the root key.
        
        Return the certificate and associated private key.
        """
        one_day = timedelta(1, 0, 0)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, host),
            ]))
        # builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.root_cert),]))
        builder = builder.issuer_name(self.root_cert.subject)

        builder = builder.not_valid_before(datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(host)]
            ),
            critical=False
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        host_cert = builder.sign(
            private_key=self.root_key, algorithm=hashes.SHA256(),
        )
        host_key = private_key
        return (host_cert, host_key)
        
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        Debug.print('Connection from {}'.format(peername))
        self.transport = transport
        self.proxy_socket = None
        self.tls = False
        self.tls_handler = None

    def handle_remote_response(self, data):
        if self.tls:
            data = self.tls_handler.encrypt_data(data)
           
        self.transport.write(data)

    def data_received(self, data):
        if self.proxy_socket:
            Debug.print("PROXY SEND:", data)
            if self.tls:
                # Responding with our own TLS response
                result_type, result = self.tls_handler.process_tls_data(data)
                if result_type == "local_response":
                    if result: self.transport.write(result)
                elif result_type == "failure":
                    Debug.print("There was an error: ", result)
                    Debug.print("Shutting down.")
                    self.transport.close()
                    self.proxy_socket.transport.close()
                elif result_type == "proxy":
                    Debug.print("Sending decrypted data to server")
                    Debug.print(result)
                    if result: self.proxy_socket.transport.write(result)
            else:
                Debug.print("Sending data to server")
                self.proxy_socket.transport.write(data)
            return

        if data.startswith(b"GET"):
            url = data.split(b" ")[1]
            o = urlparse(url.decode())
            serverport = o.netloc
            if ":" in serverport:
                server, port = serverport.split(":")
            else:
                server, port = serverport, 80
            port = int(port)
            coro = asyncio.get_event_loop().create_connection(lambda: ProxySocket(self, data), server, port, ssl=False)
            asyncio.get_event_loop().create_task(coro)
            return

        # No socket, we need to see CONNECT.
        if not data.startswith(b"CONNECT"):
            Debug.print("Unknown method", data)
            self.transport.close()
            return

        Debug.print("Got CONNECT command:", data)
        serverport = data.split(b" ")[1]
        server, port = serverport.split(b":")
        port=int(port)

        if port == 443:
            self.tls = True
            #raise Exception("Not yet implemented")
            cert, key = self.generate_proxy_crypto(server.decode())
            self.tls_handler = TLS_Visibility(cert, key)
        
        coro = asyncio.get_event_loop().create_connection(lambda: ProxySocket(self, send_connect_response=True), server, port, ssl=self.tls)
        Debug.print("Port {}. TLS? {}".format(port, self.tls))
        asyncio.get_event_loop().create_task(coro)

    def connection_lost(self, exc):
        if not self.proxy_socket: return
        self.proxy_socket.transport.close()
        self.proxy_socket = None


class TLSFrontend(asyncio.Protocol):
    def __init__(self, tls_cert, tls_key, proxy_port):
        super().__init__()
        self.tls_cert = tls_cert
        self.tls_key  = tls_key
        self.proxy_port = proxy_port
        self.backlog = b""
        
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        Debug.print('Connection from {}'.format(peername))
        self.transport = transport
        self.proxy_socket = None
        self.tls_handler = TLS_Visibility(self.tls_cert, self.tls_key)
        coro = asyncio.get_event_loop().create_connection(lambda: ProxySocket(self), "127.0.0.1", self.proxy_port, ssl=False)
        t = asyncio.get_event_loop().create_task(coro)
        t.add_done_callback(self.proxy_connected)
        
    def proxy_connected(self, task):
        if not self.proxy_socket:
            raise Exception("Unable to connect to backend server")
        if self.backlog:
            Debug.print("Writing backlog to proxy")
            self.proxy_socket.transport.write(self.backlog)
            self.backlog = b""

    def handle_remote_response(self, data):
        data = self.tls_handler.encrypt_data(data)   
        self.transport.write(data)

    def data_received(self, data):   
        Debug.print("PROXY SEND:", data)

        # Responding with our own TLS response
        result_type, result = self.tls_handler.process_tls_data(data)
        if result_type == "local_response":
            if result: self.transport.write(result)
        elif result_type == "failure":
            Debug.print("Failed.", result)
            self.transport.close()
        elif result_type == "proxy":
            Debug.print("Sending decrypted data to server")
            Debug.print(result)
            if result: 
                if not self.proxy_socket:
                    self.backlog += result
                else:
                    self.proxy_socket.transport.write(result)

    def connection_lost(self, exc):
        if not self.proxy_socket: return
        self.proxy_socket.transport.close()
        self.proxy_socket = None
        
class ProxySocket(asyncio.Protocol):
    CONNECTED_RESPONSE = (
        b"HTTP/1.0 200 Connection established\n"
        b"Proxy-agent: East Antarctica Spying Agency\n\n")

    def __init__(self, proxy, send_immediately=b"", send_connect_response=False):
        self.proxy = proxy
        self.backlog = send_immediately
        self.send_connect_response = send_connect_response

    def connection_made(self, transport):
        self.transport = transport
        self.proxy.proxy_socket = self
        if self.backlog:
            self.transport.write(self.backlog)
            self.backlog = b""
        if self.send_connect_response:
            self.proxy.transport.write(self.CONNECTED_RESPONSE)

    def data_received(self, data):
        print("PROXY RECV:", data)
        self.proxy.handle_remote_response(data)

    def connection_lost(self, exc):
        self.proxy.transport.close()
        
def main(args): 
    # uncomment the next line to turn on debug
    # debug.enabled = True
    mode = args[0]
    if mode == "proxy":
        
        frontend_port, backend_port, tls_cert, tls_key = args[1:]
        with open(tls_cert, "rb") as cert_obj:
            cert = x509.load_pem_x509_certificate(cert_obj.read())
        with open(tls_key, "rb") as key_obj:
            priv_key = load_pem_private_key(key_obj.read(), password=None)
            
        proxy_factory = lambda: TLSFrontend(cert, priv_key, backend_port)
            
    elif mode == "https-proxy":
        frontend_port, root_cert_file, root_key_file = args[1:]
        with open(root_cert_file, "rb") as cert_obj:
            root_cert = x509.load_pem_x509_certificate(cert_obj.read())
        with open(root_key_file, "rb") as key_obj:
            root_key = load_pem_private_key(key_obj.read(), password=None)
    
        proxy_factory  = lambda: TLSHTTPProxy(root_cert, root_key)
        
    else:
        raise Exception("Unknown mode {}".format(mode))
    
    loop = asyncio.get_event_loop()
    coro = loop.create_server(proxy_factory, '127.0.0.1', frontend_port)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    print('TLS front-end running on port {} in mode {}'.format(frontend_port, mode))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__=="__main__":

    ### DEBUG Option1: Printing to screen
    Debug.config_logging(True, f=sys.stdout)
    ### DEBUG Option2: Save reply
    with open("tls_replay.bin", "wb+") as replay_writer:
        Debug.config_record(True, writer=replay_writer)
        main(sys.argv[1:])