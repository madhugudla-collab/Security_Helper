import requests

FORBIDDEN_URL = "http://localhost:8081/etc/shadow"

def test_security_block():
    print(f"Agent attempting to access: {FORBIDDEN_URL}")
    response = requests.get(FORBIDDEN_URL)
    
    # If the gateway is doing its job, it won't be a 200
    if response.status_code in [403, 500]:
        print(f"--- SUCCESS: Gateway Intercepted & Stopped the request (Status {response.status_code}) ---")
        if response.headers.get("X-Security-Status") == "BLOCKED-BY-GATEWAY":
            print("Confirmed: Custom Security Header found.")
    else:
        print(f"FAILURE: Request allowed with status {response.status_code}")

test_security_block()