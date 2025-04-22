import requests
import random
import json
import os
from urllib.parse import quote

class SpotifyChecker:
    def __init__(self):
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]

    def get_random_ua(self):
        return random.choice(self.user_agents)

    def check_email(self, email):
        try:
            headers = {
                'Accept': '*/*',
                'Pragma': 'no-cache',
                'User-Agent': self.get_random_ua()
            }
            
            url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={quote(email)}"
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "That email is already registered to an account" in response.text:
                    return {"status": "Success", "message": "Email exists"}
                elif "status\":1" in response.text:
                    return {"status": "Failure", "message": "Email does not exist"}
            
            return {"status": "Error", "message": "Invalid response"}
            
        except Exception as e:
            return {"status": "Error", "message": str(e)}

    def __str__(self):
        return "Config By : @TingeeCracking"

def main():
    checker = SpotifyChecker()
    
    # Example usage
    email = "test@example.com"
    result = checker.check_email(email)
    print(f"Result for {email}: {result}")

if __name__ == "__main__":
    main()
