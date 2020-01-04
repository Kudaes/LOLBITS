import base64
import gzip
import array
import sys
import io


FILE = sys.argv[1]
PASSWORD = sys.argv[2]
OUTPUT = sys.argv[3]


def crypt(key, data):
    S = list(range(256))
    j = 0

    for i in list(range(256)):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    j = 0
    y = 0
    out = []

    for char in data:
       j = (j + 1) % 256
       y = (y + S[j]) % 256
       S[j], S[y] = S[y], S[j]
       out.append(char ^ S[(S[j] + S[y]) % 256])
       
    return out

def lee_archivo(path):

    f = open(path, "rb") # read binary data
    s = f.read() # read all bytes into a string
    return array.array("B", s) # "f" for float

def write_archivo(path, encriptado):
    out_file = open(path, "wb") 
    out_file.write(encriptado)
    out_file.close()


def ByteToHex (bytestring):
    s = ''.join('{:02x}'.format(x) for x in bytestring)
    return s

def gzipstream ( string ):
	out = io.BytesIO()
	with gzip.GzipFile(fileobj=out, mode='w') as fo:
		fo.write(string.encode())
	bytes_obj = out.getvalue()
	return base64.b64encode(bytes_obj)


datos = lee_archivo(FILE)
key = [ord(char) for char in PASSWORD]
encriptado = crypt (PASSWORD, datos)
bytearray_encriptado = encriptado
hex_encriptado = ByteToHex(bytearray_encriptado)
payload_encriptado = gzipstream(hex_encriptado)
write_archivo(OUTPUT, payload_encriptado)