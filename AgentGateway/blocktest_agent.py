import requests

FORBIDDEN_URL = "http://localhost:8081/etc/shadow"

def test_security_block():
    print(f"Agent attempting to access: {FORBIDDEN_URL}")
    try:
        response = requests.get(FORBIDDEN_URL)
        
        # Check the status code first before trying to parse JSON
        if response.status_code in [403, 500]:
            print(f"--- SUCCESS: Gateway BLOCKED the request (Status {response.status_code}) ---")
        elif response.status_code == 200:
            print("FAILURE: The request was allowed through!")
        
        # Only try to parse JSON if the content type is correct
        if "application/json" in response.headers.get("Content-Type", ""):
            print("Response Data:", response.json())
        else:
            print("Response Text:", response.text if response.text else "[Empty Body]")

    except Exception as e:
        print(f"Error: {e}")

test_security_block()