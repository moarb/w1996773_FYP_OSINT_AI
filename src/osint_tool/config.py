from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseModel):
    virustotal_api_key: str | None = os.getenv("VIRUSTOTAL_API_KEY")
    data_dir: str = "data"

settings = Settings()
