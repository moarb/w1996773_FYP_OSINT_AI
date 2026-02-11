import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()


def get_vt_key() -> str | None:
    # 1) Streamlit Cloud secrets
    try:
        import streamlit as st
        if "VIRUSTOTAL_API_KEY" in st.secrets:
            return st.secrets["VIRUSTOTAL_API_KEY"]
    except Exception:
        pass

    # 2) Local environment variables / .env
    return os.getenv("VIRUSTOTAL_API_KEY")


class Settings(BaseModel):
    virustotal_api_key: str | None = get_vt_key()
    data_dir: str = "data"


settings = Settings()
