import urllib.request, json
req = urllib.request.Request('http://172.16.0.4:80/skr/release', data=json.dumps({'runtime_data':'dGVzdA=='}).encode(), headers={'Content-Type':'application/json'}, method='POST')
try:
    resp = urllib.request.urlopen(req, timeout=60)
    body = resp.read().decode()
except urllib.error.HTTPError as e:
    body = e.read().decode()
d = json.loads(body)
sr = d.get('sidecar_response','')
print('Length:', len(sr))
print(sr)
