
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)


import crypt
import hashlib
import string
import bcrypt
password = "abc"

# salt = "$y$j9T$Lln2/jq9Yr2SknQTRoeXv/$"

# hashed = crypt.crypt(password, salt)
# print(hashed)
# print(hashed.decode() == salt)
# zgbwvbmDVB4g4hwGgitHl8ooPZZkFY0fOlYVpTyQnz3

legal_chars = (string.ascii_lowercase +
                            string.ascii_uppercase +
                            string.digits +
                            "@#%^&*()_+-=.,:;?")
password = "abc"

# print(len(legal_chars))
# MD5
# $1$EyLjrGd4$iTikz43yubbpapXByefnR.

# SHA-256
# $5$jCn9QAhUdvQl340i$06kg9eUfkygDELu/lRBMdCrWHYjSv8pdKlqEMtXvhC0

# SHA-512
# $6$KBtFC/nQfHdT7WZE$RRpU59X7XcbtX/QQ2mJamCuChrTQe47SgRl.z4a4APpOnf8YCP0/1bLYdlllCk6cULlJcczweygkQLO2yLWFC/

# bcrypt
# $2b$05$5tWeu9RE4wiQ.RWTSDBebOaone9Wz2cILBmCN7zGI65CiRlMfCCdW
rounds = "05"
salthash = "5tWeu9RE4wiQ.RWTSDBebOaone9Wz2cILBmCN7zGI65CiRlMfCCdW"

salt = salthash[:22]
hashed_password = salthash[22:]
print(f"$2b${rounds}${salt}")
hashed = bcrypt.hashpw(password.encode(), f"$2b${rounds}${salt}".encode())
print(hashed.decode())

#$2b$05$5tWeu9RE4wiQ.RWTSDBebO
#$2b$05$5tWeu9RE4wiQ.RWTSDBebO
"""
$2b$05$5tWeu9RE4wiQ.RWTSDBebOaone9Wz2cILBmCN7zGI65CiRlMfCCdW
$2b$05$5tWeu9RE4wiQ.RWTSDBebO$aone9Wz2cILBmCN7zGI65CiRlMfCCdW
"""