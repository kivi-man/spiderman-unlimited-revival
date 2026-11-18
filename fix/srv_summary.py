"""Summarise fake-server traffic from a smfix_net.log: one line per request with status,
plus the request body (truncated). Usage: python srv_summary.py net.log [--full]"""
import re
import sys

full = '--full' in sys.argv
data = open(sys.argv[1], 'rb').read().decode('utf-8', 'replace')
events = re.split(r'\n=== (\S+) (\S+) (\S+) len=(\d+)\n', '\n' + data)
# events: ['', ts, kind, ctx, len, payload, ts, kind, ...]
rows = []
for i in range(1, len(events) - 4, 5):
    ts, kind, _ctx, _n, payload = events[i:i + 5]
    rows.append((ts, kind, payload))

req = None
for ts, kind, payload in rows:
    if kind == 'SRV-REQ':
        req = {'line': payload.split('\r\n', 1)[0], 'body': ''}
    elif kind == 'SRV-REQ-BODY' and req:
        req['body'] = payload
    elif kind == 'SRV-MISS' and req:
        req['miss'] = True
    elif kind == 'SRV-RESP' and req:
        tag = 'MISS' if req.get('miss') else ' ok '
        print(f'{ts} [{tag}] {req["line"]}')
        if req['body']:
            print('        body:', req['body'] if full else req['body'][:300])
        if full:
            print('        resp:', payload[:2000])
        req = None
    elif kind == 'URL' and full:
        print(f'{ts} URL {payload}')
