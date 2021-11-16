import asyncio, time, struct
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac # avoid name collision
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from scapy.all import *
from scapy.layers.tls.keyexchange import _TLSSignature
from scapy.layers.tls.handshake import _TLSCKExchKeysField
from datetime import datetime, timedelta

from .debug import Debug
from .utils import DHParamsSerialization

randstring = Debug.replayable(Debug.random)
timestamp  = Debug.replayable(time.time)
ServerDHParams = Debug.replayable(ServerDHParams, DHParamsSerialization)

class TLSSession:
    def __init__(self):
        # manually set value
        self.tls_version = 0x303
        self.read_seq_num = 0
        self.write_seq_num = 0
        self.PRF = PRF()

        self.client_time = None
        self.client_random_bytes = None
        
        self.server_time = None
        self.server_random_bytes = None

        self.server_rsa_privkey = None
        self.client_dh_params = None

        self.mac_key_size = 20
        self.enc_key_size = 16
        self.iv_size = 16

        self.handshake = True

        # automatically calculated
        self.client_random = None
        self.server_random = None
        self.server_dh_params = ServerDHParams()
        #self.server_dh_params.fill_missing()
        self.server_dh_privkey = self.server_dh_params.tls_session.server_kx_privkey
        self.client_dh_pubkey = None
        self.pre_master_secret = None
        self.master_secret = None
        self.read_mac = None
        self.write_mac = None
        self.read_enc = None
        self.write_enc = None
        self.read_iv = None
        self.write_iv = None
        self.key_block_len = (2*self.mac_key_size)+(2*self.enc_key_size)#+(2*self.iv_size)

        self.handshake_messages = b""

    def set_client_random(self, time_part, random_part):
        # STUDENT TODO
        """
        1. set client_time, client_bytes
        2. calculate client_random. There is a method for this
        """
        self.client_time = time_part
        self.client_bytes = random_part
        self.client_random = self.time_and_random(time_part, random_part)

    def set_server_random(self):
        # STUDENT TODO
        """
        1. set server_time, server_bytes
        2. calculate server_random. There is a method for this
        """
        self.server_time = self.client_time
        # Debug.print("after randstring")

        self.server_random = self.time_and_random(self.server_time)
        self.server_random_bytes = self.server_random[4:]
        self.server_bytes = randstring(32)

    def set_server_rsa_privkey(self, rsa_privkey):
        self.server_rsa_privkey = rsa_privkey

    def set_client_dh_params(self, client_params):
        self.client_dh_params = client_params  
        p = pkcs_os2ip(self.server_dh_params.dh_p)
        g = pkcs_os2ip(self.server_dh_params.dh_g)
        pn = dh.DHParameterNumbers(p,g)
        y = pkcs_os2ip(self.client_dh_params.dh_Yc)
        public_key_numbers = dh.DHPublicNumbers(y, pn)
        self.client_dh_pubkey = public_key_numbers.public_key(default_backend())
        self._derive_keys()

    def _derive_keys(self):
        # STUDENT TODO
        """
        1. calculate pre_master_secret
        2. calculate master_secret
        3. calculate a key block
        4. split the key block into read and write keys for enc and mac
        """
        self.pre_master_secret = self.server_dh_privkey.exchange(self.client_dh_pubkey)
        pms = self.pre_master_secret
        cr = self.client_random
        sr = self.server_random
        self.master_secret = self.PRF.compute_master_secret(pms, cr, sr)
        kb = self.PRF.derive_key_block(self.master_secret, sr, cr, self.key_block_len)
        mac_size = self.mac_key_size
        enc_size = self.enc_key_size
        self.read_mac = kb[0:mac_size]
        self.write_mac = kb[mac_size:2*mac_size]
        self.read_enc = kb[2*mac_size:2*mac_size + enc_size]
        self.write_enc = kb[2*mac_size + enc_size:2*mac_size + 2*enc_size]

    def tls_sign(self, bytes):
        """
        1. Create a TLSSignature object. set sig_alg to 0x0401
        2. use this object to sign the bytes
        """
        sig = _TLSSignature(sig_alg=0x0401)
        sig._update_sig(bytes, self.server_rsa_privkey)
        return sig


    def decrypt_tls_pkt(self, tls_pkt, **kargs):
        # scapy screws up and changes the first byte if it can't decrypt it
        # from 22 to 23 (handshake to application). Check if this happens and fix
        packet_type = tls_pkt.type
        tls_pkt_bytes = raw(tls_pkt)
        tls_pkt_bytes = struct.pack("!B",packet_type)+tls_pkt_bytes[1:]
        
        # STUDENT TODO
        """
        1. The beginning of this function, already provided, extracts the data from scapy
        2. Do the TLS decryption process on tls_pkt_bytes
        3. Technically, you don't have to do the hmac. wget will do it right
        4. But if you check the hmac, you'll know your implementation is correct!
        5. return ONLY the decrypted plaintext data
        6. NOTE: When you do the HMAC, don't forget to re-create the header with the plaintext len!
        """
        iv = tls_pkt_bytes[5:self.iv_size+5]
        cipher = Cipher(algorithms.AES(self.read_enc), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(tls_pkt_bytes[5 + self.iv_size:]) + decryptor.finalize()
        # do i need to remove the padding at end?
        plaintext = plaintext[: -20 - plaintext[-1] - 1]
        return plaintext

    def encrypt_tls_pkt(self, tls_pkt, test_iv=None):
        pkt_type = tls_pkt.type
        tls_pkt_bytes = raw(tls_pkt)

        # scapy can make some mistakes changing the first bytes on handshakes
        if tls_pkt_bytes[0] != pkt_type:
            Debug.print(tls_pkt_bytes[0], pkt_type)
            tls_pkt_bytes = struct.pack("!B",pkt_type)+tls_pkt_bytes[1:]
        
        # no matter what, should only have one msg
        plaintext_msg = tls_pkt.msg[0]
        plaintext_bytes = raw(plaintext_msg)
        
        # STUDENT TODO
        """
        1. the beginning of this function, already provided, extracts the data from scapy
        2. Do the TLS encryption process on the plaintext_bytes
        3. You have to do hmac. This is the write mac key
        4. You have to compute a pad
        5. You can use os.urandom(16) to create an explicit IV
        6. return the iv + encrypted data
        """
        
        plaintext = struct.pack("!Q", self.write_seq_num)
        self.write_seq_num += 1
        prefix = struct.pack("!B", tls_pkt_bytes[0]) + tls_pkt_bytes[1:3]
        plaintext += prefix
        plaintext += struct.pack("!H", len(plaintext_bytes)) + plaintext_bytes
        iv = randstring(16)
        cipher = Cipher(algorithms.AES(self.write_enc), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        hmac = crypto_hmac.HMAC(self.write_mac, hashes.SHA1(), default_backend())
        hmac.update(plaintext)
        hmac = hmac.finalize()
        padding = self.iv_size - 1
        padding -= (len(plaintext_bytes) + len(hmac)) % self.iv_size
        padding = struct.pack("!B", padding) * padding
        msg_with_padding = plaintext_bytes + hmac + padding + struct.pack("!B", len(padding))
        ciphertext = encryptor.update(msg_with_padding) + encryptor.finalize()
        ciphertext = struct.pack("!H", len(iv + ciphertext)) + iv + ciphertext
        ciphertext = prefix + ciphertext
        return ciphertext
        
        return ciphertext

    def record_handshake_message(self, m):
        self.handshake_messages += m

    def compute_handshake_verify(self, mode):
        # STUDENT TODO
        """
        1. use PRF.compute_verify_data to compute the handshake verify data
            arg_1: the string "server"
            arg_2: mode
            arg_3: all the handshake messages so far
            arg_4: the master secret
        """
        verify_data = self.PRF.compute_verify_data("server", mode, self.handshake_messages, self.master_secret)
        
        return verify_data

    def time_and_random(self, time_part, random_part=None):
        if random_part is None:
            random_part = randstring(28)
        return struct.pack("!I",time_part) + random_part

        
        