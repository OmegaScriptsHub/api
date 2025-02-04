from fastapi import FastAPI, HTTPException
import requests

app = FastAPI()

# Hotmail inbox checker function
def check_hotmail_inbox(email: str, password: str):
    login_url = "https://login.live.com/ppsecure/post.srf"
    
    payload = {
        "login": email,
        "passwd": password
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    session = requests.Session()
    response = session.post(login_url, data=payload, headers=headers)

    if "Sign in" in response.text or response.status_code != 200:
        return {"status": "failed", "message": "Invalid credentials"}
    
    return {"status": "success", "message": "Login successful"}

@app.get("/")
def home():
    return {"message": "Hotmail Inbox Checker API"}

@app.post("/check")
def check(email: str, password: str):
    try:
        result = check_hotmail_inbox(email, password)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
