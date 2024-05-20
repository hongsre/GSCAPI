from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    dp_hms: list = ["HS256", "RS256"]
    # jwt_create.py Module을 이용해서 생성한 key를 적어주세요
    key: str = b'jwt_create.py로 생성된 Key'


settings = Settings()