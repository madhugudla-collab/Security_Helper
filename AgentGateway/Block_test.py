import requests

# Point to the "forbidden" path we defined in the security-policy.yaml
FORBIDDEN_URL = "http://localhost:8081/etc/shadow"

def test_security_block():
    print(f"Agent attempting to access protected path: {FORBIDDEN_URL}")
    
    try:
        # The gateway should intercept this and return a 403 or redirect
        response = requests.get(FORBIDDEN_URL)
        
        if response.status_code == 403:
            print("--- SUCCESS: Gateway BLOCKED the request! ---")
            print(f"Reason: Path '{FORBIDDEN_URL}' is restricted by security-helper-block policy.")
        elif response.status_code == 200:
            print("--- FAILURE: Gateway ALLOWED the request. ---")
            print("Check if the policy was applied correctly with 'kubectl get httproute'")
        else:
            print(f"Gateway returned status code: {response.status_code}")
            
    except Exception as e:
        print(f"Error connecting to gateway: {e}")

if __name__ == "__main__":
    test_security_block()