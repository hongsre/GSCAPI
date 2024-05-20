from fastapi import FastAPI
from .route import get_sts_credentials


app = FastAPI()
app.include_router(get_sts_credentials.route)