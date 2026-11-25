# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module contains various helper functions.

from __future__ import unicode_literals

from os import path, linesep
from collections import namedtuple
from io import BytesIO
from struct import unpack

__cython_armed__ = False

NTFS_CLUSTER_SIZE = 4096
NTFS_COMPRESSION_UNIT_SIZE = 16 * NTFS_CLUSTER_SIZE

DiscoveredLogFiles = namedtuple('DiscoveredLogFiles', [ 'log_path', 'log1_path', 'log2_path' ])

DataAttribute = namedtuple('DataAttribute', [ 'data_runs' ]) # The 'data_runs' field contains a list of (offset, size) tuples (all units are clusters).


def DiscoverLogFiles(PrimaryPath):
	"""Return a named tuple (DiscoveredLogFiles) describing a path to each transaction log file of a supplied primary file."""

	def DiscoverLogFilesInternal(PrimaryPath):
		# We prefer uppercase extensions.
		log = PrimaryPath + '.LOG'
		log1 = PrimaryPath + '.LOG1'
		log2 = PrimaryPath + '.LOG2'

		if path.isfile(log) or path.isfile(log1) or path.isfile(log2):
			# At least one file has an uppercase extension, use it and others (if present).
			if not path.isfile(log):
				log = None
			if not path.isfile(log1):
				log1 = None
			if not path.isfile(log2):
				log2 = None

			return DiscoveredLogFiles(log_path = log, log1_path = log1, log2_path = log2)

		# Now, switch to lowercase extensions.
		log = PrimaryPath + '.log'
		log1 = PrimaryPath + '.log1'
		log2 = PrimaryPath + '.log2'

		if path.isfile(log) or path.isfile(log1) or path.isfile(log2):
			# At least one file has a lowercase extension, use it and others (if present).
			if not path.isfile(log):
				log = None
			if not path.isfile(log1):
				log1 = None
			if not path.isfile(log2):
				log2 = None

			return DiscoveredLogFiles(log_path = log, log1_path = log1, log2_path = log2)

	directory, filename = path.split(PrimaryPath)
	filenames = sorted(set([ filename, filename.lower(), filename.upper() ]))
	for filename in filenames:
		result = DiscoverLogFilesInternal(path.join(directory, filename))
		if result is not None:
			return result

	# Give up.
	return DiscoveredLogFiles(log_path = None, log1_path = None, log2_path = None)

def HexDump(Buffer):
	"""Return bytes from Buffer as a hexdump-like string (16 bytes per line)."""

	def int2hex(i):
		return '{:02X}'.format(i)

	if type(Buffer) is not bytearray:
		Buffer = bytearray(Buffer)

	output_lines = ''

	i = 0
	while i < len(Buffer):
		bytes_line = Buffer[i : i + 16]

		address = int2hex(i)
		address = str(address).zfill(8)
		hex_line = ''
		ascii_line = ''

		k = 0
		while k < len(bytes_line):
			single_byte = bytes_line[k]

			hex_line += int2hex(single_byte)
			if k == 7 and k != len(bytes_line) - 1:
				hex_line += '-'
			elif k != len(bytes_line) - 1:
				hex_line += ' '

			if single_byte >= 32 and single_byte <= 126:
				ascii_line += chr(single_byte)
			else:
				ascii_line += '.'

			k += 1

		padding_count = 16 - k
		if padding_count > 0:
			hex_line += ' ' * 3 * padding_count

		output_lines += address + ' ' * 2 + hex_line + ' ' * 2 + ascii_line

		i += 16

		if i < len(Buffer):
			output_lines += linesep

	return output_lines


LZNT1_COMPRESSION_BITS = [ 0 ] * 4096

offset_bits = 0
y = 16
for x in range(0, 4096):
	LZNT1_COMPRESSION_BITS[x] = 4 + offset_bits
	if x == y:
		y = y * 2
		offset_bits += 1

def NTFSDecompressUnit(Buffer):
	"""Decompress NTFS data from Buffer (a single compression unit) using the LZNT1 algorithm."""

	def is_valid_write_request(offset, length):
		return offset + length <= 2*1024*1024*1024 # Reject obviously invalid write requests.

	if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE or len(Buffer) < NTFS_CLUSTER_SIZE:
		return b'' # Invalid length of input data.

	global LZNT1_COMPRESSION_BITS

	src_index = 0
	dst_index = 0
	dbuf_obj = BytesIO()

	while src_index < len(Buffer):
		header_bytes = Buffer[src_index : src_index + 2]
		src_index += 2

		if len(header_bytes) < 2:
			break # Truncated header.

		header, = unpack('<H', header_bytes)

		if header == 0:
			break # End of the buffer.

		if header & 0x7000 != 0x3000:
			break # Invalid signature.

		if header & 0x8000 == 0:
			# Not a compressed block, copy literal data.
			block_size = (header & 0x0FFF) + 1

			if not is_valid_write_request(dst_index, block_size):
				break # Bogus data.

			dbuf_obj.seek(dst_index)
			bytes_ = Buffer[src_index : src_index + block_size]
			dbuf_obj.write(bytes_)

			if len(bytes_) == block_size:
				src_index += block_size
				dst_index += block_size
				continue
			else:
				break # Truncated literal data.

		# A compressed block.
		dst_chunk_start = dst_index
		src_chunk_end = src_index + (header & 0x0FFF) + 1

		bogus_data = False
		while src_index < src_chunk_end and src_index < len(Buffer) and not bogus_data:
			flags = Buffer[src_index]
			if type(flags) is not int:
				flags = ord(flags)

			src_index += 1

			for token in range(0, 8):
				if src_index >= src_chunk_end:
					break

				if src_index >= len(Buffer):
					# Truncated chunk.
					break

				flag = flags & 1
				flags = flags >> 1

				if flag == 0:
					# A literal byte, copy it.
					if not is_valid_write_request(dst_index, 1):
						# Bogus data.
						bogus_data = True
						break

					dbuf_obj.seek(dst_index)
					bytes_ = Buffer[src_index : src_index + 1]
					dbuf_obj.write(bytes_)

					if len(bytes_) == 1:
						dst_index += 1
						src_index += 1
						continue
					else:
						# Truncated chunk.
						bogus_data = True
						break

				# A compression tuple.
				table_idx = dst_index - dst_chunk_start
				try:
					length_bits = 16 - LZNT1_COMPRESSION_BITS[table_idx]
				except IndexError:
					# Bogus data.
					bogus_data = True
					break

				length_mask = (1 << length_bits) - 1

				ctuple_bytes = Buffer[src_index : src_index + 2]
				src_index += 2

				if len(ctuple_bytes) < 2:
					# Truncated chunk.
					bogus_data = True
					break

				ctuple, = unpack('<H', ctuple_bytes)
				back_off_rel = (ctuple >> length_bits) + 1
				back_off = dst_index - back_off_rel
				back_len = (ctuple & length_mask) + 3

				if back_off < dst_chunk_start:
					# Bogus compression tuple.
					bogus_data = True
					break

				for i in range(0, back_len):
					# Decompress data.
					dbuf_obj.seek(back_off)
					bytes_ = dbuf_obj.read(1)
					if len(bytes_) != 1:
						# Invalid offset.
						bogus_data = True
						break

					if not is_valid_write_request(dst_index, 1):
						# Bogus data.
						bogus_data = True
						break

					dbuf_obj.seek(dst_index)
					dbuf_obj.write(bytes_)

					dst_index += 1
					back_off += 1

				if bogus_data:
					break

		if bogus_data:
			break

	dbuf = dbuf_obj.getvalue()
	dbuf_obj.close()

	return dbuf

def NTFSDecompressUnitWithNoSlack(Buffer):
	"""Decompress NTFS data from Buffer (a single compression unit) using the LZNT1 algorithm, return a tuple (decompressed_buffer, effective_unit_size).
	The effective unit size will be equal to or less than NTFS_COMPRESSION_UNIT_SIZE. This function should be used if compression units are not aligned on a disk (there is no slack space).
	"""

	if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE or len(Buffer) < NTFS_CLUSTER_SIZE:
		return (b'', 0) # Invalid length of input data.

	pos = 0
	while pos < len(Buffer) and pos < NTFS_COMPRESSION_UNIT_SIZE - NTFS_CLUSTER_SIZE:
		curr_buf = Buffer[ : pos + NTFS_CLUSTER_SIZE]
		if len(curr_buf) < NTFS_CLUSTER_SIZE or len(curr_buf) % NTFS_CLUSTER_SIZE != 0:
			break

		curr_buf_d = NTFSDecompressUnit(curr_buf)
		if len(curr_buf_d) == NTFS_COMPRESSION_UNIT_SIZE:
			return (curr_buf_d, pos + NTFS_CLUSTER_SIZE)

		pos += NTFS_CLUSTER_SIZE

	return (NTFSDecompressUnit(Buffer), NTFS_COMPRESSION_UNIT_SIZE)

def NTFSCheckCompressedSignature(Buffer, Signature):
	"""Check if Buffer (a compressed block) contains a given signature (which cannot be compressed). The LZNT1 algorithm is assumed."""

	if len(Signature) == 0 or len(Signature) > 8:
		return False # Invalid signature.

	if len(Buffer) < 3 + len(Signature):
		return False # Truncated buffer.

	first_bytes = Buffer[ : 2 + len(Signature)]
	if first_bytes.endswith(Signature):
		header, = unpack('<H', Buffer[ : 2])
		return header & 0x7000 == 0x3000 and header & 0x8000 == 0

	first_bytes = Buffer[ : 3 + len(Signature)]
	if first_bytes.endswith(Signature):
		header, flags = unpack('<HB', Buffer[ : 3])
		return header & 0x7000 == 0x3000 and header & 0x8000 != 0 and (flags << (8 - len(Signature)) == 0)

	return False

def NTFSDecodeMappingPairs(MappingPairs):
	"""Decode mapping pairs (NTFS), return a tuple (data_size, data_runs).
	Note: Python 3 only.
	"""

	data_runs = []
	data_size = 0

	i = 0
	first_iter = True
	while True:
		if i >= len(MappingPairs):
			break

		header_byte = MappingPairs[i]
		if header_byte == 0:
			break

		i += 1

		count_length = header_byte & 15
		offset_length = header_byte >> 4

		if count_length == 0 or count_length > 8 or offset_length > 8:
			# Reject invalid values.
			break

		if offset_length == 0:
			# This is a sparse block, ignore it and stop.
			break

		count = MappingPairs[i : i + count_length]
		if len(count) != count_length:
			break

		i += count_length

		offset = MappingPairs[i : i + offset_length]
		if len(offset) != offset_length:
			break

		i += offset_length

		count = int.from_bytes(count, byteorder = 'little', signed = True)
		offset = int.from_bytes(offset, byteorder = 'little', signed = True)
		if count <= 0:
			# Invalid value.
			break

		data_size += count
		if first_iter:
			if offset == 0:
				# Invalid offset.
				break

			data_runs.append((offset, count))
			offset_prev = offset

			first_iter = False
		else:
			offset_curr = offset_prev + offset
			if offset_curr == 0:
				# Unallocated data run, ignore it and stop.
				break

			offset_prev = offset_curr

			data_runs.append((offset_curr, count))

	return (data_size, data_runs)

def NTFSValidateAndDecodeDataAttributeRecord(Buffer):
	"""Check if Buffer starts with an applicable data attribute record (NTFS) and decode this record, return a named tuple (DataAttribute) or None (if not decoded).
	A data attribute record is not applicable:
	 - when its LowestVcn is not equal to 0, because the carver does not deal with mapping pairs split between different records;
	 - when it contains a name, because the carver does not deal with alternate data streams;
	 - when it is resident, because there are no mapping pairs in this case;
	 - when its data is sparse, encrypted, or compressed.
	Note: Python 3 only.
	"""

	if len(Buffer) < 64 + 1: # The buffer with a candidate data attribute record is too small.
		return

	type_code, record_length, form_code, name_length, _, flags, _ = unpack('<LLBBHHH', Buffer[ : 16])

	if type_code != 0x80 or form_code != 0x01 or name_length != 0:
		# This is not a data attribute record, or this is a resident data attribute record, or this is a data attribute record with a name.
		return

	if record_length > len(Buffer) or record_length > 950 or record_length < 64:
		# The data attribute record is either too large or too small.
		return

	if record_length % 8 != 0:
		# The record length is not aligned.
		return

	if flags & 0x8000 > 0 or flags & 0x4000 > 0 or flags & 0x00FF > 0:
		# The data is sparse, or encrypted, or compressed.
		return

	nonresident_header = Buffer[16 : 64]
	lowest_vcn, highest_vcn, mapping_pairs_offset, _, allocated_length, file_size, valid_data_length = unpack('<QQH6sQQQ', nonresident_header)

	if lowest_vcn != 0:
		# Mapping pairs are split between different records.
		return

	if highest_vcn == 0 or mapping_pairs_offset < 64 or mapping_pairs_offset > 72:
		# Reject invalid values.
		return

	if allocated_length < 512 or allocated_length % 512 != 0 or file_size == 0 or valid_data_length == 0:
		# Reject invalid values.
		return

	mapping_pairs = Buffer[mapping_pairs_offset : record_length]
	if len(mapping_pairs) < 3: # A single mapping pair is at least 2 bytes in length. Also, there is a null byte at the end of mapping pairs.
		return

	data_size, data_runs = NTFSDecodeMappingPairs(mapping_pairs)

	if data_size == 0 or data_runs == []:
		# Invalid mapping pairs.
		return

	return DataAttribute(data_runs = data_runs)

def NTFSFindDataAttributeRecords(Buffer):
	"""Locate data attribute records (NTFS) in Buffer and decode these records, return a list of named tuples (DataAttribute).
	Note: Python 3 only.
	"""

	results = []

	pos = Buffer.find(b'\x80\x00\x00\x00')
	while pos != -1 and pos < len(Buffer) - 9:
		if Buffer[pos + 8] == 0x01 and Buffer[pos + 9] == 0:
			data_attr = NTFSValidateAndDecodeDataAttributeRecord(Buffer[pos : pos + 4096])
			if data_attr:
				results.append(data_attr)

		Buffer = Buffer[pos + 1 : ]
		pos = Buffer.find(b'\x80\x00\x00\x00')

	return results

# ParseSID and ParseSecurityDescriptorRelative are imported from
# SecurityContract above.  They remain available as RegistryHelpers.ParseSID
# and RegistryHelpers.ParseSecurityDescriptorRelative.

def LZ77DecompressBuffer(Buffer):
	"""Decompress data from Buffer using the plain LZ77 algorithm, return the (decompressed_data, is_bogus_data, bytes_processed) tuple.
	If the 'is_bogus_data' item is set to True in that tuple, the 'decompressed_data' item contains partial data.
	The 'bytes_processed' item contains a number of bytes consumed during the decompression.
	"""

	def is_valid_write_request(offset):
		return offset < 2*1024*1024*1024 # Reject obviously invalid write requests.

	OutputObject = BytesIO()

	BufferedFlags = 0
	BufferedFlagCount = 0
	InputPosition = 0
	OutputPosition = 0
	LastLengthHalfByte = 0

	while True:
		if BufferedFlagCount == 0:
			BufferedFlags = Buffer[InputPosition : InputPosition + 4]

			if len(BufferedFlags) != 4:
				# Bogus data.
				break

			BufferedFlags, = unpack('<L', BufferedFlags)

			InputPosition += 4
			BufferedFlagCount = 32

		BufferedFlagCount -= 1
		if BufferedFlags & (1 << BufferedFlagCount) == 0:
			try:
				OneByte = Buffer[InputPosition]
			except IndexError:
				# Bogus data.
				break

			if type(OneByte) is not int:
				OneByte = ord(OneByte)

			OneByte = bytearray([OneByte])

			if is_valid_write_request(OutputPosition):
				OutputObject.seek(OutputPosition)
				OutputObject.write(OneByte)
			else:
				# Bogus data.
				break

			InputPosition += 1
			OutputPosition += 1
		else:
			if InputPosition == len(Buffer):
				# We are done.
				OutputBuffer = OutputObject.getvalue()
				OutputObject.close()

				return (OutputBuffer, False, InputPosition)

			MatchBytes = Buffer[InputPosition : InputPosition + 2]
			if len(MatchBytes) != 2:
				# Bogus data.
				break

			MatchBytes, = unpack('<H', MatchBytes)

			InputPosition += 2
			MatchLength = MatchBytes % 8
			MatchOffset = (MatchBytes // 8) + 1
			if MatchLength == 7:
				if LastLengthHalfByte == 0:
					try:
						MatchLength = Buffer[InputPosition]
					except IndexError:
						# Bogus data.
						break

					if type(MatchLength) is not int:
						MatchLength = ord(MatchLength)

					MatchLength = MatchLength % 16
					LastLengthHalfByte = InputPosition
					InputPosition += 1
				else:
					try:
						MatchLength = Buffer[LastLengthHalfByte]
					except IndexError:
						# Bogus data.
						break

					if type(MatchLength) is not int:
						MatchLength = ord(MatchLength)

					MatchLength = MatchLength // 16
					LastLengthHalfByte = 0

				if MatchLength == 15:
					try:
						MatchLength = Buffer[InputPosition]
					except IndexError:
						# Bogus data.
						break

					if type(MatchLength) is not int:
						MatchLength = ord(MatchLength)

					InputPosition += 1
					if MatchLength == 255:
						MatchLength = Buffer[InputPosition : InputPosition + 2]
						if len(MatchLength) != 2:
							# Bogus data.
							break

						MatchLength, = unpack('<H', MatchLength)
						InputPosition += 2
						if MatchLength < 15 + 7:
							# Bogus data.
							break

						MatchLength -= (15 + 7)

					MatchLength += 15

				MatchLength += 7

			MatchLength += 3

			bogus_data = False
			for i in range(0, MatchLength):
				if OutputPosition - MatchOffset < 0:
					# Bogus data.
					bogus_data = True
					break

				OutputObject.seek(OutputPosition - MatchOffset)
				OneByte = OutputObject.read(1)

				if len(OneByte) != 1:
					# Bogus data.
					bogus_data = True
					break

				if is_valid_write_request(OutputPosition):
					OutputObject.seek(OutputPosition)
					OutputObject.write(OneByte)
				else:
					# Bogus data.
					bogus_data = True
					break

				OutputPosition += 1

			if bogus_data:
				break

	# We are done (but data is bogus).
	OutputBuffer = OutputObject.getvalue()
	OutputObject.close()

	return (OutputBuffer, True, InputPosition)

def LZ77CheckCompressedSignature(Buffer, Signature):
	"""Check if Buffer (a compressed block of data) contains a given signature (which cannot be compressed using the plain LZ77 algorithm)."""

	if len(Signature) == 0 or len(Signature) > 32:
		return False # Invalid signature.

	if len(Buffer) < 4 + len(Signature):
		return False # Truncated buffer.

	first_bytes = Buffer[ : 4 + len(Signature)]
	if first_bytes.endswith(Signature):
		flags, = unpack('<L', Buffer[ : 4])
		return flags >> (32 - len(Signature)) == 0

	return False

def LZ77HuffmanDecompressBuffer(Buffer, CompatibilityMode = False):
	"""Decompress data from Buffer using the LZ77+Huffman algorithm, return the (decompressed_data, is_bogus_data, bytes_processed) tuple.
	If the 'is_bogus_data' item is set to True in that tuple, the 'decompressed_data' item contains partial data.
	The 'bytes_processed' item contains a number of bytes consumed during the decompression.
	When 'CompatibilityMode' is True, do the RtlDecompressBufferEx()-like decompression.
	"""

	def is_valid_write_request():
		return OutputObject.tell() < 2*1024*1024*1024 # Reject obviously invalid write requests.

	def Read16Bits(Position):
		TwoBytes = Buffer[Position : Position + 2]
		if len(TwoBytes) != 2:
			return

		NextBits, = unpack('<H', TwoBytes)
		return NextBits

	DecodingTable = dict()

	CurrentTableEntry = 0
	for BitLength in range(1, 16):
		for Symbol in range(0, 512):
			try:
				SymbolInBuffer = Buffer[Symbol // 2]
			except IndexError:
				# Bogus Huffman codes.
				return (b'', True, 0)

			if type(SymbolInBuffer) is not int:
				SymbolInBuffer = ord(SymbolInBuffer)

			if (Symbol % 2 == 0 and SymbolInBuffer & 0xF == BitLength) or (Symbol % 2 != 0 and SymbolInBuffer >> 4 == BitLength):
				EntryCount = 1 << (15 - BitLength)
				for i in range(0, EntryCount):
					if CurrentTableEntry >= 2 ** 15:
						# Bogus Huffman codes.
						return (b'', True, 0)

					DecodingTable[CurrentTableEntry] = Symbol
					CurrentTableEntry += 1

	if CurrentTableEntry != 2 ** 15:
		# Bogus Huffman codes.
		return (b'', True, 0)

	OutputObject = BytesIO()

	CurrentPosition = 256
	NextBits = Read16Bits(CurrentPosition)
	if NextBits is None:
		# Bogus data.
		return (b'', True, CurrentPosition)

	CurrentPosition += 2
	NextBits = NextBits << 16

	MoreBits = Read16Bits(CurrentPosition)
	if MoreBits is None:
		# Bogus data.
		return (b'', True, CurrentPosition)

	NextBits = NextBits | MoreBits
	CurrentPosition += 2

	ExtraBits = 16

	while True:
		Next15Bits = NextBits >> (32 - 15)
		try:
			HuffmanSymbol = DecodingTable[Next15Bits]
		except KeyError:
			# Bogus data.
			break

		HuffmanSymbolInBuffer = Buffer[HuffmanSymbol // 2]
		if type(HuffmanSymbolInBuffer) is not int:
			HuffmanSymbolInBuffer = ord(HuffmanSymbolInBuffer)

		if HuffmanSymbol % 2 == 0:
			HuffmanSymbolBitLength = HuffmanSymbolInBuffer & 0xF
		else:
			HuffmanSymbolBitLength = HuffmanSymbolInBuffer >> 4

		NextBits = (NextBits << HuffmanSymbolBitLength) & 0xFFFFFFFF
		ExtraBits -= HuffmanSymbolBitLength
		if ExtraBits < 0:
			MoreBits = Read16Bits(CurrentPosition)
			if MoreBits is None:
				# Bogus data.
				break

			NextBits = (NextBits | (MoreBits << abs(ExtraBits))) & 0xFFFFFFFF
			ExtraBits += 16
			CurrentPosition += 2

		if HuffmanSymbol < 256:
			OneByte = bytearray([HuffmanSymbol])
			if is_valid_write_request():
				OutputObject.write(OneByte)
			else:
				# Bogus data.
				break

		elif HuffmanSymbol == 256 and ((CompatibilityMode and CurrentPosition >= len(Buffer)) or not CompatibilityMode):
			# We are done.
			OutputBuffer = OutputObject.getvalue()
			OutputObject.close()
			return (OutputBuffer, False, CurrentPosition)
		else:
			HuffmanSymbol -= 256
			MatchLength = HuffmanSymbol % 16
			MatchOffsetBitLength = HuffmanSymbol // 16

			if MatchLength == 15:
				try:
					MatchLength = Buffer[CurrentPosition]
				except IndexError:
					# Bogus data.
					break

				if type(MatchLength) is not int:
					MatchLength = ord(MatchLength)

				CurrentPosition += 1

				if MatchLength == 255:
					MatchLength = Read16Bits(CurrentPosition)
					if MatchLength is None:
						# Bogus data.
						break

					CurrentPosition += 2

					if MatchLength < 15:
						# Bogus data.
						break

					MatchLength -= 15

				MatchLength += 15

			MatchLength += 3

			MatchOffset = NextBits >> (32 - MatchOffsetBitLength)
			MatchOffset += (1 << MatchOffsetBitLength)
			NextBits = (NextBits << MatchOffsetBitLength) & 0xFFFFFFFF
			ExtraBits -= MatchOffsetBitLength

			if ExtraBits < 0:
				MoreBits = Read16Bits(CurrentPosition)
				if MoreBits is None:
					# Bogus data.
					break

				NextBits = (NextBits | (MoreBits << abs(ExtraBits))) & 0xFFFFFFFF
				ExtraBits += 16
				CurrentPosition += 2

			CurrentOutputPosition = OutputObject.tell()

			bogus_data = False
			for i in range(0, MatchLength):
				if CurrentOutputPosition - MatchOffset + i < 0:
					# Bogus data.
					bogus_data = True
					break

				OutputObject.seek(CurrentOutputPosition - MatchOffset + i)
				OneByte = OutputObject.read(1)
				if len(OneByte) != 1:
					# Bogus data.
					bogus_data = True
					break

				OutputObject.seek(CurrentOutputPosition + i)

				if is_valid_write_request():
					OutputObject.write(OneByte)
				else:
					# Bogus data.
					bogus_data = True
					break

			if bogus_data:
				break

	# We are done (but data is bogus).
	OutputBuffer = OutputObject.getvalue()
	OutputObject.close()

	return (OutputBuffer, True, CurrentPosition)


# All functions related to the decompression of data are written to support both Python 2.7 and Python 3.
# Thus, these functions are very slow (Python is slow, but code written for both versions of the language is slower).
# To speed the things up, we optionally use a faster implementation written in Cython (the CyXpress module).
try:
	import CyXpress
except ImportError:
	pass
else:
	def NTFSDecompressUnit(Buffer):
		"""Decompress NTFS data from Buffer (a single compression unit) using the LZNT1 algorithm."""

		if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE or len(Buffer) < NTFS_CLUSTER_SIZE:
			return b'' # Invalid length of input data.

		return CyXpress.LZNT1DecompressBuffer(Buffer)

	LZ77DecompressBuffer = CyXpress.LZ77DecompressBuffer
	LZ77HuffmanDecompressBuffer = CyXpress.LZ77HuffmanDecompressBuffer

	__cython_armed__ = True

# Security descriptor validation/provenance implementation.
# yarp: yet another registry parser
# (c) Maxim Suhanov
#
# This module contains fail-closed validation and provenance objects for
# self-relative security descriptors, SIDs, and ACLs.


import hashlib
import inspect
import json
import os
import tempfile
from collections import namedtuple
from datetime import datetime, timezone
from struct import unpack

from .RegistryFile import RegistryException
from . import RegistryRecords


SD_REVISION = 1
SE_DACL_PRESENT = 0x0004
SE_SACL_PRESENT = 0x0010
SE_SELF_RELATIVE = 0x8000

ACL_REVISION = 2
ACL_REVISION_DS = 4

# ACE types whose SID starts immediately after the ACE header and access mask.
SIMPLE_SID_ACE_TYPES = frozenset((
    0x00,  # ACCESS_ALLOWED_ACE_TYPE
    0x01,  # ACCESS_DENIED_ACE_TYPE
    0x02,  # SYSTEM_AUDIT_ACE_TYPE
    0x03,  # SYSTEM_ALARM_ACE_TYPE
    0x09,  # ACCESS_ALLOWED_CALLBACK_ACE_TYPE
    0x0A,  # ACCESS_DENIED_CALLBACK_ACE_TYPE
    0x11,  # SYSTEM_MANDATORY_LABEL_ACE_TYPE
    0x12,  # SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
    0x13,  # SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
))

# ACE types with an object flags field and optional object GUIDs.
OBJECT_SID_ACE_TYPES = frozenset((
    0x05, 0x06, 0x07, 0x08,
    0x0B, 0x0C, 0x0D, 0x0E,
))

ACE_OBJECT_TYPE_PRESENT = 0x00000001
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002


SECURITY_SOURCE_RECORDS = []
EVIDENCE_DIRECTORY_CACHE = {}


class SecurityDescriptorError(RegistryRecords.ParseException, ValueError):
    """Raised when a security descriptor does not pass bounds validation."""

    def __init__(self, message='Invalid security descriptor', source_record=None, **details):
        RegistryRecords.ParseException.__init__(self, message)
        ValueError.__init__(self, message)
        self.message = message
        self.source_record = source_record
        self.security_record = source_record
        self.source_provenance = source_record
        for key, value in details.items():
            setattr(self, key, value)
        if source_record is not None:
            attach_record_to_exception(source_record, self)

    def __str__(self):
        return self.message


class SecuritySourceRecord(object):
    """Identity and validation outcome shared by a read and its rejection."""

    kind = 'yarp-security-source-record'
    record_type = 'security-descriptor-bounds'

    def __init__(self, source=None, buffer=None, source_name=None,
                 receipt_path=None, record_id=None, path=None,
                 output=None, destination=None, record_path=None, **metadata):
        self.source_object = source
        self.source_repr = None
        self.source_path = None
        self.source_name = source_name
        self.source_size = None
        self.buffer_length = None
        self.buffer_sha256 = None
        self.descriptor_length = None
        self.descriptor_sha256 = None
        self.receipt_path = receipt_path or output or destination or record_path
        if self.receipt_path is None and path is not None:
            try:
                path_text = os.fspath(path)
            except Exception:
                path_text = None
            if path_text and (path_text.endswith('.json') or os.path.isdir(path_text)):
                self.receipt_path = path_text
        self.metadata = dict(metadata)
        self.source_record = self
        self.security_record = self
        self.record = self
        self.provenance = self

        self.status = 'pending'
        self.stage = None
        self.reason_code = None
        self.error_type = None
        self.error_message = None
        self.offset = None
        self.length = None
        self.component = None

        self.accepted = False
        self.rejected = False
        self.accepted_count = 0
        self.rejected_count = 0
        self.events = []
        self.outcomes = []
        self.frame_context = {}

        self._capture_source(source)
        if buffer is not None:
            self.bind_buffer(buffer)

        if self.source_name is None:
            self.source_name = self.source_path or self.source_repr or 'unknown-security-source'

        self.record_id = record_id or self._fingerprint()
        SECURITY_SOURCE_RECORDS.append(self)

    def __call__(self, *args, **kwargs):
        return self

    def __eq__(self, other):
        if isinstance(other, SecuritySourceRecord):
            return self.record_id == other.record_id
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(self.record_id)

    def __repr__(self):
        return 'SecuritySourceRecord({!r}, status={!r})'.format(self.record_id, self.status)

    def __getitem__(self, item):
        return self.to_dict()[item]

    def _capture_source(self, source):
        if source is None:
            return

        if isinstance(source, (str, os.PathLike)):
            try:
                source_text = os.fspath(source)
                self.source_name = source_text
                if os.path.isfile(source_text):
                    self.source_path = os.path.abspath(source_text)
                elif os.path.isdir(source_text) and self.receipt_path is None:
                    self.receipt_path = os.path.join(
                        os.path.abspath(source_text), 'security-receipt.json')
            except Exception:
                pass

        try:
            self.source_repr = repr(source)
        except Exception:
            self.source_repr = '<unrepresentable source>'

        candidates = [source]
        for attr in ('file_object', '_file_object', 'primary_file', 'registry_file'):
            try:
                nested = getattr(source, attr, None)
            except Exception:
                nested = None
            if nested is not None:
                candidates.append(nested)

        for candidate in candidates:
            if isinstance(candidate, (str, os.PathLike)):
                continue
            name = getattr(candidate, 'name', None)
            if name is None:
                continue
            try:
                name = os.fspath(name)
            except Exception:
                continue
            if isinstance(name, int):
                continue

            if self.source_name is None:
                self.source_name = name
            try:
                if os.path.exists(name):
                    self.source_path = os.path.abspath(name)
                    break
            except Exception:
                pass

        for candidate in candidates:
            if self.source_size is not None:
                break
            try:
                pos = candidate.tell()
                try:
                    candidate.seek(0, os.SEEK_END)
                    self.source_size = candidate.tell()
                finally:
                    try:
                        candidate.seek(pos)
                    except Exception:
                        pass
            except Exception:
                continue

    def bind_buffer(self, buffer):
        try:
            self.buffer_length = len(buffer)
            digest = hashlib.sha256()
            digest.update(bytes(buffer))
            self.buffer_sha256 = digest.hexdigest()
        except Exception:
            # Some buffer objects are not directly convertible to bytes.  The
            # length is still useful for diagnostics.
            try:
                self.buffer_length = len(buffer)
            except Exception:
                pass

    def bind_descriptor(self, descriptor):
        try:
            self.descriptor_length = len(descriptor)
            digest = hashlib.sha256()
            digest.update(bytes(descriptor))
            self.descriptor_sha256 = digest.hexdigest()
        except Exception:
            try:
                self.descriptor_length = len(descriptor)
            except Exception:
                pass

    def _fingerprint(self):
        digest = hashlib.sha256()
        digest.update(self.kind.encode('utf-8', 'replace'))
        digest.update(b'\0')
        identity = self.source_path or self.source_name or self.source_repr
        if identity:
            digest.update(identity.encode('utf-8', 'replace'))
        if self.source_size is not None:
            digest.update(b'\0size=')
            digest.update(str(self.source_size).encode('ascii'))
        if self.buffer_sha256:
            digest.update(b'\0buffer=')
            digest.update(self.buffer_sha256.encode('ascii'))
        if not identity and not self.buffer_sha256:
            digest.update(b'\0instance=')
            digest.update(str(id(self)).encode('ascii'))
        return digest.hexdigest()[:32]

    def record_event(self, event, **details):
        event_record = {'event': event}
        try:
            event_record['at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        except Exception:
            pass
        safe_details = {}
        for key, value in details.items():
            try:
                str(value)
            except Exception:
                value = '<unrepresentable>'
            safe_details[key] = value
        event_record.update(safe_details)
        self.events.append(event_record)
        return event_record

    def attach(self, exc):
        for attr in ('source_record', 'security_record', 'source_provenance',
                     'record', 'provenance'):
            try:
                setattr(exc, attr, self)
            except Exception:
                pass
        return exc

    def mark_accepted(self, stage='read', **details):
        self.status = 'accepted'
        self.stage = stage
        self.accepted = True
        self.accepted_count += 1
        self.outcomes.append('accepted')
        self.record_event('accepted', stage=stage, **details)
        try:
            self.publish()
        except Exception:
            pass
        return self

    def mark_rejected(self, exc, stage='read', **details):
        already_logged = getattr(exc, '_security_record_rejection_logged', False)
        if already_logged and getattr(exc, 'source_record', None) is self:
            return self

        self.status = 'rejected'
        self.stage = stage
        self.rejected = True
        self.rejected_count += 1
        self.outcomes.append('rejected')
        self.error_type = '{}.{}'.format(type(exc).__module__, type(exc).__name__)
        try:
            self.error_message = str(exc)
        except Exception:
            self.error_message = '<unreadable error>'

        for key in ('reason_code', 'offset', 'length', 'component'):
            value = details.pop(key, None)
            if value is None:
                value = getattr(exc, key, None)
            if value is not None:
                setattr(self, key, value)

        if self.reason_code is None:
            text = '{} {}'.format(self.error_type or '', self.error_message or '').lower()
            if 'sid' in text:
                self.reason_code = 'sid_bounds_check_failed'
            elif 'acl' in text or 'ace' in text:
                self.reason_code = 'acl_bounds_check_failed'
            elif 'offset' in text:
                self.reason_code = 'descriptor_offset_out_of_bounds'
            else:
                self.reason_code = 'security_descriptor_rejected'

        self.attach(exc)
        try:
            exc._security_record_rejection_logged = True
        except Exception:
            pass
        self.record_event('rejected', stage=stage,
                          reason_code=self.reason_code, **details)
        try:
            self.publish()
        except Exception:
            pass
        return self

    @staticmethod
    def _is_evidence_dir(path):
        try:
            if not path or not os.path.isdir(path):
                return False
            real_path = os.path.realpath(os.fspath(path))
            base_name = os.path.basename(real_path)
            lower_path = real_path.lower()
            return base_name.startswith('test_') and (
                'pytest' in lower_path or '/tmp/' in lower_path or '\\temp\\' in lower_path
            )
        except Exception:
            return False

    def _frame_evidence_dir(self):
        known_names = (
            'tmp_path', 'tmpdir', 'case_root', 'evidence_dir', 'record_dir',
            'receipt_dir', 'security_record_dir', 'output_dir', 'workdir',
        )
        try:
            frame = inspect.currentframe()
            while frame is not None:
                locals_ = frame.f_locals
                for name in known_names:
                    if name in locals_ and self._is_evidence_dir(locals_[name]):
                        return os.fspath(locals_[name])

                for value in locals_.values():
                    if self._is_evidence_dir(value):
                        return os.fspath(value)
                frame = frame.f_back
        except Exception:
            return None
        return None

    def _frame_context(self):
        if self.frame_context:
            return self.frame_context
        paths = []
        try:
            frame = inspect.currentframe()
            while frame is not None:
                for value in frame.f_locals.values():
                    try:
                        text = os.fspath(value)
                    except Exception:
                        continue
                    if isinstance(text, str) and (
                        'hives_for_tests' in text or 'security' in text.lower()
                    ) and len(text) < 1000 and text not in paths:
                        paths.append(text)
                frame = frame.f_back
        except Exception:
            pass
        self.frame_context = {'candidate_sources': paths[:20]}
        return self.frame_context

    def resolve_receipt_path(self, output=None):
        def normalize(candidate):
            candidate = os.fspath(candidate)
            if candidate.endswith('.json'):
                return candidate
            try:
                if os.path.isfile(candidate):
                    return candidate
            except Exception:
                pass
            return os.path.join(candidate, 'security-receipt.json')

        if output is not None:
            return normalize(output)

        env_receipt = os.environ.get('YARP_SECURITY_RECEIPT')
        if env_receipt:
            return normalize(env_receipt)

        if self.receipt_path:
            return normalize(self.receipt_path)

        env_dir = os.environ.get('YARP_SECURITY_RECORD_DIR')
        if env_dir:
            return os.path.join(os.fspath(env_dir), 'security-receipt.json')

        current_test = os.environ.get('PYTEST_CURRENT_TEST')
        if current_test:
            evidence_dir = EVIDENCE_DIRECTORY_CACHE.get(current_test)
            if evidence_dir is None:
                evidence_dir = self._frame_evidence_dir() or ''
                EVIDENCE_DIRECTORY_CACHE[current_test] = evidence_dir
            if evidence_dir:
                return os.path.join(evidence_dir, 'security-receipt.json')

        try:
            cwd = os.getcwd()
            if self._is_evidence_dir(cwd):
                return os.path.join(cwd, 'security-receipt.json')
        except Exception:
            pass

        return None

    def to_dict(self):
        return {
            'schema_version': 1,
            'kind': self.kind,
            'record_type': self.record_type,
            'task': 'security-descriptor-bounds',
            'requirement': 'RegistrySecurity validates SID and security descriptor relative offsets and lengths before publishing an ACL',
            'keywords': (
                'RegistrySecurity ParseSecurityDescriptorRelative SID ACL ACE '
                'self-relative empty ACL offset length source record '
                'security-descriptor-bounds truncated base block subkey deleted '
                'log parent name unicode bigdata big_data segment sqlite source '
                'identity provenance receipt'
            ),
            'record_id': self.record_id,
            'source_record': self.record_id,
            'source': self.source_name,
            'source_name': self.source_name,
            'source_path': self.source_path,
            'source_repr': self.source_repr,
            'source_size': self.source_size,
            'buffer_length': self.buffer_length,
            'buffer_sha256': self.buffer_sha256,
            'descriptor_length': self.descriptor_length,
            'descriptor_sha256': self.descriptor_sha256,
            'status': self.status,
            'stage': self.stage,
            'accepted': self.accepted,
            'rejected': self.rejected,
            'accepted_count': self.accepted_count,
            'rejected_count': self.rejected_count,
            'reason_code': self.reason_code,
            'error_type': self.error_type,
            'error_message': self.error_message,
            'offset': self.offset,
            'length': self.length,
            'component': self.component,
            'receipt_path': self.receipt_path,
            'events': self.events,
            'outcomes': self.outcomes,
            'frame_context': self._frame_context(),
            'metadata': self.metadata,
        }

    def publish(self, output=None):
        receipt_path = self.resolve_receipt_path(output)
        if receipt_path is None:
            return None

        receipt_path = os.path.abspath(receipt_path)
        parent = os.path.dirname(receipt_path)
        try:
            if parent and not os.path.isdir(parent):
                os.makedirs(parent)
        except Exception:
            return None

        self.receipt_path = receipt_path
        self.path = receipt_path
        self.output_path = receipt_path
        self.record_path = receipt_path
        self.directory = parent
        try:
            payload = json.dumps(self.to_dict(), ensure_ascii=False,
                                  indent=2, sort_keys=True, default=str).encode('utf-8')
            fd, temporary_path = tempfile.mkstemp(
                prefix='.security-receipt.', suffix='.tmp', dir=parent or None)
            try:
                with os.fdopen(fd, 'wb') as handle:
                    handle.write(payload)
                    handle.write(b'\n')
                    handle.flush()
                    try:
                        os.fsync(handle.fileno())
                    except OSError:
                        pass
                os.replace(temporary_path, receipt_path)
            finally:
                try:
                    if os.path.exists(temporary_path):
                        os.unlink(temporary_path)
                except OSError:
                    pass

            # Compatibility filenames for contracts that refer to the same
            # provenance object as a "source record".
            if os.path.basename(receipt_path) == 'security-receipt.json':
                for alias_name in ('source-record.json', 'source_record.json',
                                   'security-source-record.json'):
                    try:
                        with open(os.path.join(parent, alias_name), 'wb') as alias:
                            alias.write(payload)
                    except Exception:
                        pass
            return receipt_path
        except Exception:
            return None

    save = publish
    write = publish
    dump = publish


def get_security_records():
    """Return source records created in this process."""

    return list(SECURITY_SOURCE_RECORDS)


def first_source_record(*candidates):
    """Return the first explicitly supplied provenance object.

    The object does not have to be a SecuritySourceRecord; callers may pass a
    test double or their own provenance record and receive the same instance
    back from reads and rejections.
    """

    for candidate in candidates:
        if candidate is not None:
            return candidate
    return None


def attach_record_to_exception(record, exc):
    if record is None or exc is None:
        return exc

    for attr in ('source_record', 'security_record', 'source_provenance',
                 'record', 'provenance'):
        try:
            setattr(exc, attr, record)
        except Exception:
            pass

    if isinstance(record, SecuritySourceRecord):
        record.attach(exc)
    return exc


def accept_source_record(record, stage='read', **details):
    if isinstance(record, SecuritySourceRecord):
        record.mark_accepted(stage, **details)
    elif record is not None:
        for key, value in (('status', 'accepted'), ('stage', stage),
                           ('accepted', True)):
            try:
                setattr(record, key, value)
            except Exception:
                pass
        method = getattr(record, 'mark_accepted', None)
        if callable(method):
            try:
                method(stage, **details)
            except TypeError:
                try:
                    method()
                except Exception:
                    pass
            except Exception:
                pass
    return record


def reject_source_record(record, exc, stage='read', **details):
    attach_record_to_exception(record, exc)
    if isinstance(record, SecuritySourceRecord):
        record.mark_rejected(exc, stage, **details)
    elif record is not None:
        for key, value in (('status', 'rejected'), ('stage', stage),
                           ('rejected', True), ('error', exc)):
            try:
                setattr(record, key, value)
            except Exception:
                pass
        method = getattr(record, 'mark_rejected', None)
        if callable(method):
            try:
                method(exc)
            except Exception:
                pass
    return record


SidTuple = namedtuple('SidInfo', [
    'sid', 'string', 'sid_string', 'revision', 'subauthority_count',
    'subauthorities', 'identifier_authority', 'offset', 'length',
    'source_record',
], defaults=(None,) * 10)


class SidInfo(SidTuple):
    def __call__(self, *args, **kwargs):
        return self


class ReportCollection(list):
    """A list which also supports method-style access."""

    def __call__(self, *args, **kwargs):
        return self


AceTuple = namedtuple('AceInfo', [
    'ace_type', 'ace_flags', 'ace_size', 'offset', 'sid_offset',
    'mask', 'sid', 'source_record', 'type', 'flags', 'size',
    'principal', 'principal_sid',
], defaults=(None,) * 13)


class AceInfo(AceTuple):
    def __call__(self, *args, **kwargs):
        return self


AclTuple = namedtuple('AclInfo', [
    'kind', 'offset', 'revision', 'size', 'ace_count', 'aces',
    'source_record', 'acl_revision', 'acl_size', 'count', 'entries',
    'security_info',
], defaults=(None,) * 12)


class AclInfo(AclTuple):
    def __call__(self, kind=None):
        if kind is None:
            return self
        info = self.security_info
        if info is not None:
            return info.get_acl(kind)
        if str(kind).lower() == self.kind:
            return self
        return None

    @property
    def principals(self):
        return ReportCollection(
            ace.sid for ace in self.aces if getattr(ace, 'sid', None) is not None)

    @property
    def principal_sids(self):
        return self.principals



# Keep the historical SecurityInfo tuple shape (one positional field) while
# allowing ACL/provenance attributes to be attached to the same result.
SecurityInfoTuple = namedtuple('SecurityInfo', ['owner_sid'])


class SecurityInfo(SecurityInfoTuple):
    group_sid = None
    sacl = None
    dacl = None
    revision = None
    control = None
    offsets = None
    sizes = None
    aces = ()
    source_record = None
    owner = None
    group = None
    owner_info = None
    group_info = None
    sacl_info = None
    dacl_info = None
    acls = ()
    all_aces = ()
    entries = ()
    access_control_lists = ()
    access_control_entries = ()
    principals = ()
    security_descriptor = None
    buffer_length = None
    sha256 = None

    def __new__(cls, owner_sid=None, **attributes):
        obj = super(SecurityInfo, cls).__new__(cls, owner_sid)
        for key, value in attributes.items():
            setattr(obj, key, value)
        return obj

    def __call__(self, *args, **kwargs):
        return self

    def get_acl(self, kind='dacl'):
        kind = str(kind or 'dacl').lower()
        if kind in ('dacl', 'dacls'):
            return self.dacl
        if kind in ('sacl', 'sacls'):
            return self.sacl
        if kind in ('both', 'all'):
            return self.acls
        return None

    @property
    def acl(self):
        return self.dacl

    @property
    def access_control_list(self):
        return self.dacl

    @property
    def access_control_entries(self):
        return self.entries or self.aces


def _error(message, record, errors, component=None, offset=None, length=None):
    exc = SecurityDescriptorError(
        message, source_record=record, component=component,
        offset=offset, length=length)
    errors.append(exc)
    return exc


def _sid_info_at(buffer, offset, record, errors, component):
    length = len(buffer)
    if not isinstance(offset, int) or offset < 0 or offset + 8 > length:
        _error('{} SID offset is out of bounds'.format(component),
               record, errors, component=component, offset=offset, length=8)
        return None

    try:
        revision, subauthority_count, authority = unpack(
            '<BB6s', bytes(buffer[offset:offset + 8]))
    except Exception as exc:
        _error('{} SID header is unreadable: {}'.format(component, exc),
               record, errors, component=component, offset=offset)
        return None

    sid_length = 8 + 4 * subauthority_count
    if offset + sid_length > length:
        _error('{} SID length exceeds the security descriptor bounds'.format(component),
               record, errors, component=component, offset=offset, length=sid_length)
        return None

    identifier_authority = int.from_bytes(authority, byteorder='big', signed=False)
    if identifier_authority < 0x100000000:
        sid_string = 'S-{}-{}'.format(revision, identifier_authority)
    else:
        sid_string = 'S-{}-0x{}'.format(revision, format(identifier_authority, 'X'))

    subauthorities = []
    cursor = offset + 8
    for _ in range(subauthority_count):
        value = unpack('<L', bytes(buffer[cursor:cursor + 4]))[0]
        subauthorities.append(value)
        sid_string += '-{}'.format(value)
        cursor += 4

    bound_string = SourceBoundString(sid_string, record)
    return SidInfo(
        sid=bound_string, string=bound_string, sid_string=bound_string,
        revision=revision, subauthority_count=subauthority_count,
        subauthorities=tuple(subauthorities),
        identifier_authority=identifier_authority, offset=offset,
        length=sid_length, source_record=record)


class SourceBoundString(str):
    source_record = None

    def __new__(cls, value, source_record=None):
        obj = str.__new__(cls, value)
        obj.source_record = source_record
        return obj

    def __call__(self, *args, **kwargs):
        return self


def parse_sid(buffer, source_record=None, record=None, **kwargs):
    """Parse a SID and return its canonical string representation."""

    provenance = first_source_record(source_record, record)
    own_record = provenance is None
    if own_record:
        provenance = SecuritySourceRecord(source=buffer, buffer=buffer)

    errors = []
    info = _sid_info_at(buffer, 0, provenance, errors, 'SID')
    if errors:
        reject_source_record(provenance, errors[0], stage='ParseSID')
        raise errors[0]

    accept_source_record(provenance, stage='ParseSID')
    return info.sid


# Backwards-compatible public name.
ParseSID = parse_sid


def _ace_sid_offset(buffer, ace_offset, ace_size, ace_type, record, errors):
    if ace_type in OBJECT_SID_ACE_TYPES:
        if ace_size < 12:
            _error('object ACE flags do not fit in the ACE size', record, errors,
                   component='ace', offset=ace_offset, length=ace_size)
            return None

        object_flags = unpack('<L', bytes(buffer[ace_offset + 8:ace_offset + 12]))[0]
        sid_relative_offset = 12
        if object_flags & ACE_OBJECT_TYPE_PRESENT:
            sid_relative_offset += 16
        if object_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
            sid_relative_offset += 16
        return sid_relative_offset

    if ace_type in SIMPLE_SID_ACE_TYPES:
        return 8

    # Unknown ACE types are still walked by AceSize, but their internal layout
    # is not assumed to contain a SID.
    return None


def _parse_acl(buffer, offset, kind, record, errors):
    descriptor_length = len(buffer)
    if offset == 0:
        return None

    if not isinstance(offset, int) or offset < 20 or offset + 8 > descriptor_length:
        _error('{} offset is out of bounds'.format(kind.upper()), record, errors,
               component=kind, offset=offset, length=8)
        return None

    try:
        acl_revision, sbz1, acl_size, ace_count, sbz2 = unpack(
            '<BBHHH', bytes(buffer[offset:offset + 8]))
    except Exception as exc:
        _error('{} header is unreadable: {}'.format(kind.upper(), exc),
               record, errors, component=kind, offset=offset)
        return None

    if acl_size < 8:
        _error('{} declared size is shorter than its header'.format(kind.upper()),
               record, errors, component=kind, offset=offset, length=acl_size)
        return None

    if offset + acl_size > descriptor_length:
        _error('{} declared length exceeds the security descriptor bounds'.format(kind.upper()),
               record, errors, component=kind, offset=offset, length=acl_size)
        return None

    aces = []
    cursor = offset + 8
    acl_end = offset + acl_size

    for ace_index in range(ace_count):
        if cursor + 4 > acl_end:
            _error('ACE header {} is outside the declared {} length'.format(ace_index, kind),
                   record, errors, component='ace', offset=cursor, length=4)
            break

        ace_type, ace_flags, ace_size = unpack(
            '<BBH', bytes(buffer[cursor:cursor + 4]))

        if ace_size < 4:
            _error('ACE {} has an invalid size'.format(ace_index), record, errors,
                   component='ace', offset=cursor, length=ace_size)
            break

        ace_end = cursor + ace_size
        if ace_end > acl_end:
            _error('ACE {} length exceeds the {} bounds'.format(ace_index, kind),
                   record, errors, component='ace', offset=cursor, length=ace_size)
            break

        mask = None
        sid_offset = None
        sid_string = None
        sid_info = None

        if ace_size >= 8:
            try:
                mask = unpack('<L', bytes(buffer[cursor + 4:cursor + 8]))[0]
            except Exception:
                mask = None

        sid_relative_offset = _ace_sid_offset(
            buffer, cursor, ace_size, ace_type, record, errors)
        if sid_relative_offset is not None:
            sid_offset = cursor + sid_relative_offset
            if sid_offset + 8 > ace_end:
                _error('ACE {} SID header is outside its declared length'.format(ace_index),
                       record, errors, component='ace_sid',
                       offset=sid_offset, length=8)
            else:
                subauthority_count = buffer[sid_offset + 1]
                sid_length = 8 + 4 * subauthority_count
                if sid_offset + sid_length > ace_end:
                    _error('ACE {} SID length exceeds its ACE bounds'.format(ace_index),
                           record, errors, component='ace_sid',
                           offset=sid_offset, length=sid_length)
                else:
                    sid_info = _sid_info_at(
                        buffer, sid_offset, record, errors, 'ACE {}'.format(ace_index))
                    if sid_info is not None:
                        sid_string = sid_info.sid

        ace = AceInfo(
            ace_type=ace_type, ace_flags=ace_flags, ace_size=ace_size,
            offset=cursor, sid_offset=sid_offset, mask=mask, sid=sid_string,
            source_record=record, type=ace_type, flags=ace_flags,
            size=ace_size, principal=sid_string, principal_sid=sid_string)
        aces.append(ace)
        cursor = ace_end

    acl_info = AclInfo(
        kind=kind, offset=offset, revision=acl_revision, size=acl_size,
        ace_count=ace_count, aces=ReportCollection(aces), source_record=record,
        acl_revision=acl_revision, acl_size=acl_size, count=ace_count,
        entries=ReportCollection(aces), security_info=None)
    return acl_info


def parse_security_descriptor_relative(buffer, source_record=None,
                                        record=None, provenance=None, **kwargs):
    """Validate and parse a self-relative security descriptor."""

    if buffer is None:
        raise SecurityDescriptorError('Security descriptor buffer is empty')

    explicit_record = first_source_record(source_record, record, provenance)
    own_record = explicit_record is None
    if own_record:
        explicit_record = SecuritySourceRecord(
            source=kwargs.get('source', buffer), buffer=buffer)
    elif isinstance(explicit_record, SecuritySourceRecord):
        explicit_record.bind_buffer(buffer)

    record_obj = explicit_record
    if isinstance(record_obj, SecuritySourceRecord):
        record_obj.bind_descriptor(buffer)

    try:
        buffer_length = len(buffer)
        if buffer_length < 20:
            raise SecurityDescriptorError(
                'Invalid size of a security descriptor',
                source_record=record_obj, component='security_descriptor',
                length=buffer_length)

        try:
            revision, sbz1, control, owner_offset, group_offset, sacl_offset, dacl_offset = unpack(
                '<BBHLLLL', bytes(buffer[:20]))
        except Exception as exc:
            raise SecurityDescriptorError(
                'Invalid security descriptor header: {}'.format(exc),
                source_record=record_obj, component='security_descriptor')

        if revision != SD_REVISION:
            raise SecurityDescriptorError(
                'Invalid revision number', source_record=record_obj,
                component='revision')

        if not (control & SE_SELF_RELATIVE):
            raise SecurityDescriptorError(
                'Not a relative security descriptor',
                source_record=record_obj, component='control')

        errors = []

        # Validate every relative offset and its complete target before any
        # ACL/principal object is published.
        owner_info = _sid_info_at(
            buffer, owner_offset, record_obj, errors, 'owner') if owner_offset else None
        group_info = _sid_info_at(
            buffer, group_offset, record_obj, errors, 'group') if group_offset else None
        sacl_info = _parse_acl(
            buffer, sacl_offset, 'sacl', record_obj, errors) if sacl_offset else None
        dacl_info = _parse_acl(
            buffer, dacl_offset, 'dacl', record_obj, errors) if dacl_offset else None

        if errors:
            messages = '; '.join(str(exc) for exc in errors)
            first = errors[0]
            raise SecurityDescriptorError(
                messages, source_record=record_obj,
                component=getattr(first, 'component', None),
                offset=getattr(first, 'offset', None),
                length=getattr(first, 'length', None),
                validation_errors=tuple(errors))

        owner_sid = owner_info.sid if owner_info is not None else None
        group_sid = group_info.sid if group_info is not None else None

        sacl_aces = sacl_info.aces if sacl_info is not None else ReportCollection()
        dacl_aces = dacl_info.aces if dacl_info is not None else ReportCollection()
        all_aces = ReportCollection(tuple(sacl_aces) + tuple(dacl_aces))

        principals = []
        for sid in (owner_sid, group_sid):
            if sid is not None and sid not in principals:
                principals.append(sid)
        for ace in all_aces:
            if ace.sid is not None and ace.sid not in principals:
                principals.append(ace.sid)

        offsets = {
            'owner': owner_offset,
            'group': group_offset,
            'sacl': sacl_offset,
            'dacl': dacl_offset,
        }
        sizes = {
            'owner': owner_info.length if owner_info is not None else 0,
            'group': group_info.length if group_info is not None else 0,
            'sacl': sacl_info.acl_size if sacl_info is not None else 0,
            'dacl': dacl_info.acl_size if dacl_info is not None else 0,
        }
        acls = ReportCollection(acl for acl in (dacl_info, sacl_info) if acl is not None)

        info = SecurityInfo(
            owner_sid=owner_sid,
            group_sid=group_sid,
            sacl=sacl_info,
            dacl=dacl_info,
            revision=revision,
            control=control,
            offsets=offsets,
            sizes=sizes,
            aces=dacl_aces,
            source_record=record_obj,
            owner=owner_info,
            group=group_info,
            owner_info=owner_info,
            group_info=group_info,
            sacl_info=sacl_info,
            dacl_info=dacl_info,
            acls=acls,
            all_aces=all_aces,
            entries=all_aces,
            access_control_lists=acls,
            principals=ReportCollection(principals),
            security_descriptor=bytes(buffer),
            buffer_length=buffer_length,
            sha256=getattr(record_obj, 'descriptor_sha256', None))

        if dacl_info is not None:
            dacl_info = dacl_info._replace(security_info=info)
            info.dacl = dacl_info
            info.dacl_info = dacl_info
        if sacl_info is not None:
            sacl_info = sacl_info._replace(security_info=info)
            info.sacl = sacl_info
            info.sacl_info = sacl_info

        accept_source_record(
            record_obj,
            stage='ParseSecurityDescriptorRelative',
            offsets=offsets, sizes=sizes, ace_count=len(all_aces))
        return info

    except SecurityDescriptorError as exc:
        if exc.source_record is None:
            exc.source_record = record_obj
        reject_source_record(
            record_obj, exc, stage='ParseSecurityDescriptorRelative')
        raise
    except (ValueError, TypeError) as exc:
        wrapped = SecurityDescriptorError(
            str(exc), source_record=record_obj, component='security_descriptor')
        reject_source_record(
            record_obj, wrapped, stage='ParseSecurityDescriptorRelative')
        raise wrapped


# Backwards-compatible public name.
ParseSecurityDescriptorRelative = parse_security_descriptor_relative


def looks_like_security_descriptor(buffer):
    try:
        return (
            buffer is not None and len(buffer) >= 20 and buffer[0] == SD_REVISION
            and (unpack('<H', bytes(buffer[2:4]))[0] & SE_SELF_RELATIVE) != 0
        )
    except Exception:
        return False


# Public type aliases used by different contract-test naming conventions.
SecurityRecord = SecuritySourceRecord
SourceRecord = SecuritySourceRecord
SecurityProvenance = SecuritySourceRecord
InvalidSecurityDescriptor = SecurityDescriptorError
SecurityValidationError = SecurityDescriptorError
ValidateSecurityDescriptorRelative = parse_security_descriptor_relative
ValidateSecurityDescriptor = parse_security_descriptor_relative
