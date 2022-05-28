#!/usr/bin/env python3

# Pedro Bautista Garcia

import binascii, os, base64, mysql.connector, json, scrypt, SecureString
from Crypto.Cipher import AES


def string_to_byte(temp):
    return bytes(temp, encoding="UTF-8")

# funcion AES para cifrar
def encrypt_AES_GCM(msg, password):
    kdfSalt = os.urandom(16)
    secretKey = scrypt.hash(password, kdfSalt, N=16384, r=8, p=1, buflen=32)
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (kdfSalt, ciphertext, aesCipher.nonce, authTag, secretKey)

# El password necesita guardarse en un archivo separado
# y que no se suba a git
with open("password.json") as file:
    data = json.load(file)
    
password = data['password']

password = string_to_byte(password)

# La idea es que estos datos vengan de otro lado como parte
# de una app mas completa, pero para la practica lo
# podrian dejar asi directo al codigo
name = "Jhon Connor"
diagnosis = "Heridas por ataque de T-800"
treatment = "Paracetamol cada 8 hrs"

diagnosis = string_to_byte(diagnosis)
treatment = string_to_byte(treatment)

# Aplicar el cifrado AES en modo de operacion GCM
diagnosis_encrypted = encrypt_AES_GCM(diagnosis, password)
treatment_encrypted = encrypt_AES_GCM(treatment, password)



print('Password:', password)
print("---------------------------------------------------------------------")
print('Diagnosis:', diagnosis)
print('Diagnosis -> PasswordSalt:', binascii.hexlify(diagnosis_encrypted[0]))
print('Diagnosis -> encrypted:', binascii.hexlify(diagnosis_encrypted[1]))
print('Diagnosis -> IV:', binascii.hexlify(diagnosis_encrypted[2]))
print('Diagnosis -> authTag:', binascii.hexlify(diagnosis_encrypted[3]))
print('Diagnosis -> AES encryption key:', binascii.hexlify(diagnosis_encrypted[4]))
print("")
print('Medical treatment:', treatment)
print('Treatment -> PasswordSalt:', binascii.hexlify(treatment_encrypted[0]))
print('Treatment -> encrypted:', binascii.hexlify(treatment_encrypted[1]))
print('Treatment -> IV:', binascii.hexlify(treatment_encrypted[2]))
print('Treatment -> authTag:', binascii.hexlify(treatment_encrypted[3]))
print('Treatment -> AES encryption key:', binascii.hexlify(treatment_encrypted[4]))


# Se codifica en base 64 los datos para ser guardados en la BD
diagnosis_passwordSalt = base64.b64encode(diagnosis_encrypted[0])
diagnosis_ciphertext = base64.b64encode(diagnosis_encrypted[1])
diagnosis_iv = base64.b64encode(diagnosis_encrypted[2])
diagnosis_autTag = base64.b64encode(diagnosis_encrypted[3])

treatment_passwordSalt = base64.b64encode(treatment_encrypted[0])
treatment_ciphertext = base64.b64encode(treatment_encrypted[1])
treatment_iv = base64.b64encode(treatment_encrypted[2])
treatment_autTag = base64.b64encode(treatment_encrypted[3])

print("---------------------------------------------------------------------")
print('Diagnosis -> PasswordSalt (base64):', diagnosis_passwordSalt)
print('Diagnosis -> encrypted (base64):', diagnosis_ciphertext)
print('Diagnosis -> IV (base64):', diagnosis_iv)
print('Diagnosis -> authTag (base64):', diagnosis_autTag)
print("")
print('Treatment -> PasswordSalt (base64):', treatment_passwordSalt)
print('Treatment -> encrypted (base64):', treatment_ciphertext)
print('Treatment -> IV (base64):', treatment_iv)
print('Treatment -> authTag (base64):', treatment_autTag)


# Guardar los datos en una base de datos relacional
try:
    # Estos datos necesitan estar en un archivo separado 
    # del programa y tampoco deben subirse a git
    # El cifrado de la conexion se realizara en otra practica
    with open("conexion_db.json") as file:
        data = json.load(file)

    mydb = mysql.connector.connect(
                                 user=data["user"],
                                 password=data["password"],
                                 host=data["host"],
                                 port=data["port"],
                                 database=data["database"])
    cursor = mydb.cursor()
    insert_query = """ INSERT INTO expediente (
                                                nombre, 
                                                diagnostico_passwordSalt, diagnostico_ciphertext, diagnostico_iv, diagnostico_autTag,
                                                tratamiento_passwordSalt, tratamiento_ciphertext, tratamiento_iv, tratamiento_autTag) 
                                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """

    record_to_insert = (
                        name, 
                        diagnosis_passwordSalt, diagnosis_ciphertext, diagnosis_iv, diagnosis_autTag, 
                        treatment_passwordSalt, treatment_ciphertext, treatment_iv, treatment_autTag)

    cursor.execute(insert_query, record_to_insert)

    mydb.commit()
    count = cursor.lastrowid
    print("---------------------------------------------------------------------")
    print("Record inserted successfully with id ", count)


except mysql.connector.Error as err:
  print("Something went wrong: {}".format(err))


finally:
    if mydb:
        cursor.close()
        mydb.close()
        print("DBMS connection is closed")




# Sobrescribir el contenido de las variables para
# evitar que se puedan obtener los datos a través de 
# un volcado de memoria RAM
SecureString.clearmem(password)
SecureString.clearmem(diagnosis)
SecureString.clearmem(treatment)
SecureString.clearmem(diagnosis_encrypted[4])
SecureString.clearmem(treatment_encrypted[4])

print("---------------------------------------------------------------------")
print('Diagnosis AES encryption key:', diagnosis_encrypted[4])
print('Treatment AES encryption key:', treatment_encrypted[4])
print('Password:', password)
print('Diagnosis:', diagnosis)
print('Treatment:', treatment)
