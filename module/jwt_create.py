import jwt
import sys
import base64
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import yaml

base = os.path.dirname(os.path.abspath(__file__))
config_path = f"{base}/.config/config.yaml"


def get_config(config_path):
    print(config_path)
    if os.path.isfile(config_path):
        print(f'{config_path} ok')
    else:
        print(f'{config_path} not found program shutdown')
        sys.exit(1)

    with open(config_path, 'r', encoding="UTF-8") as f:
        config = yaml.load(f,Loader=yaml.FullLoader)
    return config


def gen_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key 


def encode_base64(token, key):
    f = Fernet(key)
    bytes_encode=token.encode('ascii')
    base64_encode = f.encrypt(bytes_encode)
    base64_token = base64_encode.decode('ascii')
    return base64_token


def decode_base64(base64_token, key):
    f = Fernet(key)
    bytes_base64_token = base64_token.encode('ascii')
    base64_decode = f.decrypt(bytes_base64_token)
    token = base64_decode.decode('ascii')
    return token


def encode_jwt(json, key, dp_hm):
    print("create JWT")
    print("---------------------------")
    token = jwt.encode(json, key, algorithm=dp_hm)
    print("base64 encoding JWT")
    print("---------------------------")
    base64_token = encode_base64(token, key)
    return base64_token


def decode_jwt(token, key, dp_hms):
    print("base64 decoding JWT")
    print("---------------------------")
    token = decode_base64(token, key)
    print("get JWT data")
    print("---------------------------")
    decode = jwt.decode(token, key, algorithms=dp_hms)
    return decode



if __name__ == "__main__":
    file = sys.argv[1]
    UID = sys.argv[2]
    json1 = json.load(open(file, 'r'))
    config = get_config(config_path)
    
    # # JWT Password 생성
    # password = b"seongi_test"
    # print(gen_key(password))
    # sys.exit()
    
    key = config['decode']['key'].encode('ascii')
    dp_hms = config['decode']['dp_hms']
    dp_hm = config['decode']['dp_hm']
    print(key)
    print(dp_hms)

    # Json을 Password로 암호화
    a = encode_jwt(json1, key, dp_hm)
    print(a)
    with (open(f'{base}/.config/{UID}_jwt', 'w')) as f:
        f.write(a)
    
    # 암호화된 Json 내용을 JWT Password를 이용한 복호화
    b = decode_jwt(a, key, dp_hms)
    print(b)