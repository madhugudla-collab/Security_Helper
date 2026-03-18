import requests

# This is the 'Entry Point' for your Security Helper
GATEWAY_URL = "http://localhost:8081/anything"

def run_security_scan():
    print(f"Agent starting: Routing request through {GATEWAY_URL}...")
    
    # Simulate your agent sending code to be 'remediated'
    payload = {
        "agent_name": "Security-Helper-v1",
        "action": "fix_vulnerability",
        "target_file": "auth.py"
    }
    
    try:
        response = requests.post(GATEWAY_URL, json=payload)
        
        if response.status_code == 200:
            print("--- Success! ---")
            # The 'json' field in the response shows what the gateway received
            received_data = response.json().get("json")
            print(f"Gateway processed action: {received_data['action']}")
        else:
            print(f"Failed to reach Gateway. Status: {response.status_code}")
            
    except Exception as e:
        print(f"Error connecting to agentgateway: {e}")

if __name__ == "__main__":
    run_security_scan()