#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from Cryptodome.Cipher import AES
import random

class AESHandler(BaseHTTPRequestHandler):
    def __init__(self, a, b, c):

        # add crypto functionality
        self._key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        self._iv  = b'\x00'*16

        # random characters to pick from when creating a message to encrypt for the user
        self._chars = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890 '

        # make sure the handler works!
        super().__init__(a, b, c)

    def pad(self, m):
         padding_len = 16 - len(m) % 16
         padding = bytes([padding_len for n in range(padding_len)])
         return m + padding
 
    def unpad(self, m):
         padding_len = m[-1]
         if 0 < padding_len < 17:
            message_bytes = [b for b in m]
            for n in range(padding_len):
                 if message_bytes.pop() != padding_len:
                     raise Exception("Bad padding")
         else:
             raise Exception("Bad padding")
         return bytes(message_bytes)

    def encrypt(self, m, include_iv=False):
        if include_iv == True:
            iv = random.randbytes(16)
        else:
            iv = self._iv

        encryptor = AES.new(self._key, AES.MODE_CBC, iv)
        ct = encryptor.encrypt(self.pad(m))
        if include_iv == True:
            ct = iv + ct
        return ct

    def decrypt(self, m, include_iv=False):
        if include_iv == True:
            iv = m[:16]
            ct = m[16:]
        else:
            iv = self._iv
            ct = m
        decryptor = AES.new(self._key, AES.MODE_CBC, iv)
        return self.unpad(decryptor.decrypt(ct))

    def random_string(self, length=-1):
        if length < 0:
            length = random.randint(33, 64)
        return ''.join([self._chars[random.randint(0, len(self._chars) - 1)] for n in range(length)])

    def do_GET (self):
        message = ''
        try:
            if self.path == '/encrypt-with-iv':
                pt = f'sid: {self.random_string()}'.encode()
                ct = self.encrypt(pt, include_iv=True)
                message = ct.hex()
                self.send_response(200)
            elif self.path == '/encrypt':
                pt = f'sid: {self.random_string()}'.encode()
                ct = self.encrypt(pt)
                message = ct.hex()
                self.send_response(200)
            elif self.path.startswith('/decrypt-with-iv'):
                ct = bytes.fromhex(self.path.split('/')[-1])
                message = self.decrypt(ct, include_iv=True).decode()
                self.send_response(200)
            elif self.path.startswith('/decrypt'):
                ct = bytes.fromhex(self.path.split('/')[-1])
                message = self.decrypt(ct).decode()
                self.send_response(200)
        except UnicodeDecodeError as ex:
            self.send_response(200)
        except Exception as ex:
            self.send_response(500)

        self.end_headers()
        self.wfile.write(bytes(message, "utf8"))

with HTTPServer(('', 8080), AESHandler) as server:
    server.serve_forever()
