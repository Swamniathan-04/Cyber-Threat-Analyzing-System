import requests
import json

BASE_URL = 'http://127.0.0.1:5000'

def test_health():
    print("\nTesting health endpoint...")
    try:
        response = requests.get(f'{BASE_URL}/api/health')
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error occurred: {e}")

def test_login():
    print("\nTesting login endpoint...")
    try:
        response = requests.post(
            f'{BASE_URL}/api/login',
            json={'email': 'admin@guardian.ai', 'password': 'Admin123!'}
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.json().get('token')
    except Exception as e:
        print(f"Error occurred: {e}")
        return None

def test_analyze(token):
    print("\nTesting analyze endpoint...")
    if not token:
        print("No token available for testing analyze endpoint")
        return
    
    try:
        response = requests.post(
            f'{BASE_URL}/api/analyze',
            headers={'Authorization': f'Bearer {token}'},
            json={'text': 'This is a test message for threat analysis'}
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == '__main__':
    test_health()
    token = test_login()
    test_analyze(token) 