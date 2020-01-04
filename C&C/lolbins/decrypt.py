import base64
import gzip
import array
import sys
import io


def lee_archivo(path):

    f = open(path, "r") # read binary data
    s = f.read() # read all bytes into a string
    return s # "f" for float

def write_archivo(path, encriptado):
    out_file = open(path, "wb") 
    out_file.write(encriptado)
    out_file.close()

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
       
    return array.array('B',out)

def unzip(bytes):
    in_ = io.BytesIO()
    in_.write(bytes)
    in_.seek(0)
    with gzip.GzipFile(fileobj=in_,mode='rb') as fo:
       gunzip = fo.read()

    return gunzip.decode()  


def decrypt(filepath, password):
    """
FILE = sys.argv[1]
PASSWORD = sys.argv[2]
OUTPUT = sys.argv[3]
"""

    datos = lee_archivo(filepath)
    key = [ord(char) for char in password]
    d = base64.b64decode(datos)
    u = unzip(d)
    enc = crypt(password,bytearray.fromhex(u))
    #write_archivo(OUTPUT, enc.tostring())
    return enc.tobytes()