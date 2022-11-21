#!/usr/bin/env python3
from padlib import PadLib
import requests

import time

VERBOSE = True

def callback(guess):
	r = requests.get(f'http://localhost:8080/decrypt-with-iv/{guess.hex()}')
	return r.status_code == 200

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
oracle = PadLib(bytes.fromhex(ciphertext), callback, crib='QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890 ', verbose=VERBOSE)
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
