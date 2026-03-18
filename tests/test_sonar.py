import requests, os
from dotenv import load_dotenv

load_dotenv('c:/Users/madhu/Projects/Security Helper/security-orch-bot/.env')
token = os.getenv('SONARQUBE_TOKEN', '')
print('Token set:', bool(token), '| starts with:', token[:15] if token else 'EMPTY')

r = requests.get(
    'http://localhost:9000/api/issues/search',
    params={'componentKeys': 'easybuggy', 'types': 'VULNERABILITY,BUG', 'ps': 5},
    auth=(token, ''),
    timeout=10
)
print('Status:', r.status_code)
if r.status_code == 200:
    d = r.json()
    total = d.get('total', 0)
    print('SAST WORKS! Total issues:', total)
    for i in d.get('issues', [])[:5]:
        sev = i.get('severity', '?')
        msg = i.get('message', '')[:70]
        comp = i.get('component', '').split(':')[-1]
        line = i.get('line', '?')
        print('  [' + sev + '] ' + msg + ' -- ' + comp + ':' + str(line))
elif r.status_code == 401:
    print('ERROR 401 - Token invalid or wrong type')
    print('You need a USER TOKEN (not Project token)')
    print()
    print('HOW TO FIX:')
    print('  1. Go to http://localhost:9000')
    print('  2. Login as admin')
    print('  3. Click top-right avatar -> My Account')
    print('  4. Click Security tab')
    print('  5. Under Generate Tokens:')
    print('       Name: security-bot')
    print('       Type: User Token  <-- IMPORTANT: must be User Token, NOT Project Token')
    print('       Expiration: No expiration')
    print('  6. Click Generate -> copy the squ_... value')
    print('  7. Paste into .env: SONARQUBE_TOKEN=squ_...')
else:
    print('Unexpected error:', r.text[:300])
