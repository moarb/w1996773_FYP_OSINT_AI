# import os
# from pydantic import BaseModel
# from dotenv import load_dotenv

# load_dotenv()


# def get_vt_key() -> str | None:
#     # 1) Streamlit Cloud secrets
#     try:
#         import streamlit as st
#         if "VIRUSTOTAL_API_KEY" in st.secrets:
#             return st.secrets["VIRUSTOTAL_API_KEY"]
#     except Exception:
#         pass

#     # 2) Local environment variables / .env
#     return os.getenv("VIRUSTOTAL_API_KEY")


# class Settings(BaseModel):
#     virustotal_api_key: str | None = get_vt_key()
#     data_dir: str = "data"


# settings = Settings()

import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()


def get_secret(name: str) -> str | None:
    # 1) Streamlit Cloud secrets
    try:
        import streamlit as st
        if name in st.secrets:
            value = str(st.secrets[name]).strip()
            return value if value else None
    except Exception:
        pass

    # 2) Local environment variables / .env
    value = os.getenv(name, "").strip()
    return value if value else None


class Settings(BaseModel):
    virustotal_api_key: str | None = get_secret("VIRUSTOTAL_API_KEY")
    shodan_api_key: str | None = get_secret("SHODAN_API_KEY")
    data_dir: str = "data"


settings = Settings()
