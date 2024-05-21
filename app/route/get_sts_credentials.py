from config.config import settings
from fastapi import APIRouter, HTTPException
from fastapi import Form
from cryptography.fernet import Fernet
import jwt
import boto3

route = APIRouter()


def decode_base64(base64_token, jwt_key):
    f = Fernet(jwt_key)
    bytes_base64_token = base64_token.encode('ascii')
    base64_decode = f.decrypt(bytes_base64_token)
    token = base64_decode.decode('ascii')
    return token


def decode_jwt(token, jwt_key, jwt_dp_hms):
    print("base64 decoding JWT")
    print("---------------------------")
    token = decode_base64(token, jwt_key)
    print("get JWT data")
    print("---------------------------")
    decode = jwt.decode(token, jwt_key, algorithms=jwt_dp_hms)
    return decode

def get_sts_credentials(jwt_info):
    try:
        if jwt_info['check']:
            # AWS STS 클라이언트 생성
            sts_client = boto3.client('sts')
            session_name = jwt_info['upload']['session_name']
            role_arn = jwt_info['upload']['arn']

            # 역할을 가정하여 임시 자격 증명 획득
            assumed_role_object = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name
            )

            # 임시 자격 증명 추출
            credentials = assumed_role_object['Credentials']

            response = {
                'status': True,
                'access_key': credentials['AccessKeyId'],
                'secret_key': credentials['SecretAccessKey'],
                'session_token': credentials['SessionToken'],
                'bucket': jwt_info['upload']['bucket'],
                'arn': jwt_info['upload']['arn'],
                'domain': jwt_info['upload']['domain']
            }
        else:
            response = {
                'status': False,
                'msg': "check please token Value"
            }
            return response
    except:
        response = {
            'status': False,
            'msg': "check please token Value"
        }
    return response

#healthcheck용 URL
@route.get('/healthcheck', tags=['send'])
async def root():  # root page 표시할 내용
    return {"message": "Hello World"}

# STS Credential 얻는 API
# 암호화된 Json 값을 파라미터로 넘겨줘야함.
@route.post("/credentials/get", tags=['send'])
async def sts_credentials(token: str = Form()):
    jwt_info = decode_jwt(token, settings.key, settings.dp_hms)
    response = get_sts_credentials(jwt_info)
    if response['status']:
        return response
    else:
        raise HTTPException(
            status_code=500,
            detail=response['msg']
        )