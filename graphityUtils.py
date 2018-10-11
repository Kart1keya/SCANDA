from hashlib import sha1, md5
from os.path import basename, getsize
#import magic
#import pydeep
import pefile
import time
import math
import struct
from io import open
from collections import Counter

# receives a string, containing a symbol a la radare2
# returns the sole API name

def gimmeDatApiName(wholeString):

	separators = ['.dll_', '.sys_', '.exe_', '.sym_']

	for sep in separators:

		if sep in wholeString:
			apiName = wholeString.split(sep)[1].replace(']','')
			return apiName

		elif sep.upper() in wholeString:
			apiName = wholeString.split(sep.upper())[1].replace(']','')
			return apiName

	return wholeString


# checks whether a string is pure ascii

def is_ascii(myString):
	try:
		myString.decode('ascii')
		return True
	except UnicodeDecodeError:
		return False

# String evaluation

def stringCharFrequency(seString):

	# english language character frequencies
	freqs = {
		'a': 0.0651738,
		'b': 0.0124248,
		'c': 0.0217339,
		'd': 0.0349835,
		'e': 0.1041442,
		'f': 0.0197881,
		'g': 0.0158610,
		'h': 0.0492888,
		'i': 0.0558094,
		'j': 0.0109033,
		'k': 0.0150529,
		'l': 0.0331490,
		'm': 0.0202124,
		'n': 0.0564513,
		'o': 0.0596302,
		'p': 0.0137645,
		'q': 0.0058606,
		'r': 0.0497563,
		's': 0.0515760,
		't': 0.0729357,
		'u': 0.0225134,
		'v': 0.0182903,
		'w': 0.0271272,
		'x': 0.0013692,
		'y': 0.0145984,
		'z': 0.0017836,
		' ': 0.0500000,
		'0': 0.0500000,
		'1': 0.0500000,
		'2': 0.0500000,
		'3': 0.0500000,
		'4': 0.0500000,
		'5': 0.0500000,
		'6': 0.0500000,
		'7': 0.0500000,
		'8': 0.0500000,
		'9': 0.0500000,
		'.': 0.0400000,
		'_': 0.0400000
	}

	score = 0

	for i in seString:
		ch = i.lower()
		if ch in freqs:
			score += freqs[ch]

	if len(seString) > 15:
		return score / float(len(seString)/2)

	return score / float(len(seString))

def stringCharVariance(seString):
	
	charFrequs = Counter(seString)
	total = 0
	for letter in charFrequs:
		if charFrequs[letter] < 4:
			total += (charFrequs[letter]-1)
		elif charFrequs[letter] < 5:
			total += (charFrequs[letter]-0.75)
		elif charFrequs[letter] < 6:
			total += (charFrequs[letter]-0.5)
		elif charFrequs[letter] < 7:
			total += (charFrequs[letter]-0.25)
		else:
			total += charFrequs[letter]


			#print (seString, total)
			
	return total / float(len(seString)*2)

# Check for PE header, return false if not a PE
def check_pe_header(filepath):
	try:
		with open(filepath, 'rb') as fp:
			if (fp.read(2) == b'MZ'):
				fp.read(58)
				peoff = struct.unpack('i', fp.read(4))
				advance = peoff[0] - 64
				fp.read(advance)
				if (fp.read(2) == b'PE'):
					return True
		return False

	except(Exception) as e:
		print("LOG - PE Parsing Error, sure this is a PE file?")
		return False
	return False


# SAMPLE ATTRIBUTE GETTERS

 # MD5
 # filename
 # filetype
 # ssdeep
 # imphash
 # size
 # compilationTS
 # address of EP
 # EP section
 # number of section
 # original filename
 # number TLS sections

def sha1hash(path):
	with open(path, 'rb') as f:
		return sha1(f.read()).hexdigest()

def md5hash(path):
	with open(path, 'rb') as f:
		return md5(f.read()).hexdigest()

def getFilename(path):
	return basename(path)

def getFiletype(path):
	return ""
#	return magic.from_file(path)

def getFilesize(path):
	return getsize(path)

def getPeSubsystem(path):
	pass

def getSsdeep(path):
	return "" # pydeep.hash_file(path)

def getImphash(pe):
	return pe.get_imphash()

def getCompilationTS(pe):
	return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(pe.FILE_HEADER.TimeDateStamp))

def getEPAddress(pe):
	return pe.OPTIONAL_HEADER.AddressOfEntryPoint

def getSectionCount(pe):
	return pe.FILE_HEADER.NumberOfSections

def getOriginalFilename(pe):
	oriFilename = ""
	if hasattr(pe, 'VS_VERSIONINFO'):
		if hasattr(pe, 'FileInfo'):
			for entry in pe.FileInfo:
				if hasattr(entry, 'StringTable'):
					for st_entry in entry.StringTable:
						ofn = st_entry.entries.get(b'OriginalFilename')
						if ofn:
							if isinstance(ofn, bytes):
								oriFilename = ofn.decode()
							else:
								oriFilename = ofn
	return oriFilename


def getEPSection(pe):
	name = ''
	if hasattr(pe, 'OPTIONAL_HEADER'):
		ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	else:
		return False
	pos = 0
	for sec in pe.sections:
		if (ep >= sec.VirtualAddress) and (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
			name = sec.Name.replace(b'\x00', b'')
			break
		else:
			pos += 1
	if name:
		return (name.decode('utf-8', 'ignore') + "|" + pos.__str__())
	return ''
		
def getTLSSectionCount(pe):
	idx = 0
	if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
		callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

		while True:
			func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
			if func == 0:
				break
			idx += 1
	return idx


# Returns Entropy value for given data chunk
def Hvalue(data):
	if not data:
		return 0.0

	occurences = Counter(bytearray(data))
	
	entropy = 0
	for x in occurences.values():
		p_x = float(x) / len(data)
		if p_x > 0:
			entropy += - p_x * math.log(p_x, 2)

	return entropy


def getCodeSectionSize(pe):

	for section in pe.sections:
		print(section)


def getSectionInfo(pe):

	# Section info: names, sizes, entropy vals
	sects = []
	vadd = []
	ent = []
	secnumber = getSectionCount(pe)
	
	for i in range(12):

		if (i + 1 > secnumber):
			strip = ""
			strap = ""
			entropy = ""

		else:
			stuff = pe.sections[i]
			strip = stuff.Name.replace(b'\x00', b'')
			strap = stuff.SizeOfRawData

			entropy = Hvalue(stuff.get_data())

		section_name = ""
		try:
			if strip != "":
				section_name = strip.decode()
		except:
			section_name = "PARSINGERR"

		sects.append(section_name)
		ent.append(entropy)
		vadd.append(strap)

	secinfo = sects + vadd + ent
	return secinfo

	
# ATTRIBUTES: md5, sha1, filename, filetype, ssdeep, filesize, imphash, compilationts, addressep, sectionep,
# sectioncount, sectioninfo, tlssections, originalfilename
	
def getAllAttributes(path):

	allAtts = {}

	allAtts['md5'] = md5hash(path)
	allAtts['sha1'] = sha1hash(path)
	allAtts['filename'] = getFilename(path)
	allAtts['filetype'] = getFiletype(path)
	allAtts['ssdeep'] = getSsdeep(path)
	allAtts['filesize'] = getFilesize(path)

	try:
		pe = pefile.PE(path)
		if (pe.DOS_HEADER.e_magic == int(0x5a4d) and pe.NT_HEADERS.Signature == int(0x4550)):
			allAtts['imphash'] = getImphash(pe)
			allAtts['compilationts'] = getCompilationTS(pe)
			allAtts['addressep'] = getEPAddress(pe)
			allAtts['sectionep'] = getEPSection(pe)
			allAtts['sectioncount'] = getSectionCount(pe)
			allAtts['sectioninfo'] = getSectionInfo(pe)
			allAtts['tlssections'] = getTLSSectionCount(pe)
			allAtts['originalfilename'] = getOriginalFilename(pe)

	except (pefile.PEFormatError):
		allAtts['imphash'] = ''
		allAtts['compilationts'] = ''
		allAtts['addressep'] = ''
		allAtts['sectionep'] = ''
		allAtts['sectioncount'] = ''
		allAtts['sectioninfo'] = ''
		allAtts['tlssections'] = ''
		allAtts['originalfilename'] = ''

	return allAtts
