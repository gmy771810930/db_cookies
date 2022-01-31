# Based on:
# 	https://gist.github.com/DakuTree/98c8362fb424351b803e
# 	https://gist.github.com/jordan-wright/5770442
# 	https://gist.github.com/DakuTree/428e5b737306937628f2944fbfdc4ffc
# 	https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies
# 	https://stackoverflow.com/questions/43987779/python-module-crypto-cipher-aes-has-no-attribute-mode-ccm-even-though-pycry

import os
import json
import base64
import sqlite3
import configparser
from shutil import copyfile

# python.exe -m pip install pypiwin32
import win32crypt
# python.exe -m pip install pycryptodomex
from Cryptodome.Cipher import AES

conf = configparser.ConfigParser()
try:
    conf.read("config.ini", encoding="utf-8-sig")
except:
    conf.read("config.ini", encoding="utf-8")

db_sites = conf.get("javdb", "sites").split(",")
db_sites.append("")

BROWSER_PROFILE_PATH = os.getenv("APPDATA") + "/../Local/Google/Chrome/User Data"
# BROWSER_PROFILE_PATH = os.getenv("APPDATA") + "/../Local/Microsoft/Edge/User Data"

# Copy Cookies and Local State to current folder
for i in db_sites:
    copyfile(BROWSER_PROFILE_PATH + "/Default/Cookies", './Cookies')

    # Load encryption key
    encrypted_key = None
    with open(BROWSER_PROFILE_PATH + "/Local State", 'r') as file:
        encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key)
    encrypted_key = encrypted_key[5:]
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

    # Connect to the Database
    conn = sqlite3.connect('./Cookies')
    cursor = conn.cursor()

    # Get the results
    cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')
    for host_key, name, value, encrypted_value in cursor.fetchall():
        # Decrypt the encrypted_value
        try:
            # Try to decrypt as AES (2020 method)
            cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=encrypted_value[3:3 + 12])
            decrypted_value = cipher.decrypt_and_verify(encrypted_value[3 + 12:-16], encrypted_value[-16:])
        except:
            # If failed try with the old method
            decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode(
                'utf-8') or value or 0

        # Update the cookies with the decrypted value
        # This also makes all session cookies persistent
        cursor.execute('\
    		UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0\
    		WHERE host_key = ?\
    		AND name = ?',
                       (decrypted_value, host_key, name));

    conn.commit()
    conn.close()

    # Export javdb.com cookies to javdb.json
    conn = sqlite3.connect('./Cookies')
    cursor = conn.cursor()
    cursor.execute('SELECT name, value FROM cookies WHERE host_key LIKE "%javdb' + i + '.com"')
    jsonfile = open('javdb' + i + '.json', mode='w')
    jsonfile.write("{\n")
    lines = 0
    last_name = ''
    last_value = ''
    for name, value in cursor.fetchall():
        lines = lines + 1
        if lines > 1:
            jsonfile.write('"' + last_name + '":"' + last_value + '",\n')
        last_name = str(name)
        last_value = value.decode("utf-8")
    conn.close()
    if lines > 0:
        jsonfile.write('"' + last_name + '":"' + last_value + '"\n')
    jsonfile.write("}\n")
    jsonfile.close()
    os.remove('./Cookies')
