import base64
import hashlib
import subprocess
import sys
import time
import ipaddress
import json
import pathlib
from tags import fields, tags

root = pathlib.Path(__file__).resolve().parent
source = root/'source.conf'
cache = root/'work'
cache.mkdir(exist_ok=True)
inputs = {
 'geosite.dat': 'https://raw.githubusercontent.com/hydraponique/roscomvpn-geosite/master/release/geosite.dat',
 'geoip.dat': 'https://raw.githubusercontent.com/hydraponique/roscomvpn-geoip/master/release/geoip.dat',
 'world-geoip.dat': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat',
 'as45090.json': 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS45090',
 'hxehex.list': 'https://raw.githubusercontent.com/forg-lib-lov/roscomvpn-shadowrocket/main/lists/hxehex-whitelist.list',
}
if '--offline' not in sys.argv:
 for name,url in inputs.items():
  temp = cache/(name+'.tmp')
  subprocess.run(['curl','-fsSL','--retry','2','--retry-all-errors','--connect-timeout','15','--max-time','120',url,'-o',str(temp)],check=True)
  if temp.stat().st_size < 100: raise ValueError('Empty source: '+name)
  temp.replace(cache/name)
p = {
    'Name': 'RoscomVPN FIX Shadow 06.26 — INCY',
    'GlobalProxy': 'true', 'RemoteDNSType': 'DoH',
    'RemoteDNSDomain': 'https://8.8.8.8/dns-query', 'RemoteDNSIP': '8.8.8.8',
    'DomesticDNSType': 'DoH', 'DomesticDNSDomain': 'https://77.88.8.8/dns-query',
    'DomesticDNSIP': '77.88.8.8',
    'Geoipurl': 'https://raw.githubusercontent.com/hydraponique/roscomvpn-geoip/master/release/geoip.dat',
    'Geositeurl': 'https://raw.githubusercontent.com/hydraponique/roscomvpn-geosite/master/release/geosite.dat',
    'RouteOrder': 'block-proxy-direct', 'DomainStrategy': 'IPIfNonMatch',
    'FakeDNS': 'false', 'useChunkFiles': False,
    **{a+b: [] for a in ('Direct','Proxy','Block') for b in ('Sites','Ip')}
}
actions = {'DIRECT': 'Direct', 'PROXY': 'Proxy', 'REJECT': 'Block'}
used = []
def add(kind, value, action):
    bucket = p[actions[action] + ('Ip' if kind in ('IP-CIDR','IP-CIDR6','GEOIP') else 'Sites')]
    value = {'DOMAIN-SUFFIX': 'domain:', 'DOMAIN': 'full:', 'DOMAIN-KEYWORD': 'keyword:'}.get(kind,'') + value
    if value not in bucket: bucket.append(value)

for line in source.read_text().split('[Rule]',1)[1].splitlines():
    line = line.strip()
    if not line or line.startswith('#'): continue
    row = line.split(','); kind, value = row[:2]
    if kind == 'FINAL': continue
    action = row[2]
    if kind == 'RULE-SET':
        name = value.rsplit('/',1)[1].removesuffix('.list')
        category = {'private-domains':'private','torrent-domains':'torrent','whitelist-domains':'whitelist',
                    'private-ips':'private','whitelist-ips':'whitelist','direct-ips':'direct'}.get(name,name)
        if name == 'hxehex-whitelist':
            for rule in (root/'work/hxehex.list').read_text().splitlines():
                if rule and not rule.startswith('#'):
                    k,v,*_ = rule.split(','); add(k,v,action)
        else:
            is_ip = name.endswith('-ips')
            assert category in tags(root/('work/geoip.dat' if is_ip else 'work/geosite.dat')), category
            field = actions[action] + ('Ip' if is_ip else 'Sites')
            p[field].append(('geoip:' if is_ip else 'geosite:')+category)
        used.append(value)
    elif kind == 'IP-ASN':
        assert value == '45090'
        for entry in json.loads((root/'work/as45090.json').read_text())['data']['prefixes']:
            add('IP-CIDR',entry['prefix'],action)
    elif kind == 'GEOIP':
        # Extract the two country lists because the custom RoscomVPN geoip only has private/direct/whitelist.
        found = False
        for number, msg in fields((root/'work/world-geoip.dat').read_bytes()):
            if number != 1: continue
            entry = list(fields(msg))
            country = next(v.decode() for k,v in entry if k==1)
            if country.lower() != value.lower(): continue
            found = True
            for k,cidr in entry:
                if k != 2: continue
                parts = dict(fields(cidr))
                network = str(ipaddress.ip_network((ipaddress.ip_address(parts[1]),parts.get(2,0)),strict=False))
                add('IP-CIDR',network,action)
        assert found, value
    else:
        assert kind in ('DOMAIN-SUFFIX','DOMAIN','DOMAIN-KEYWORD','IP-CIDR','IP-CIDR6'), kind
        add(kind,value,action)

# Collapse snapshot networks to shorten the import URL, preserving every address.
networks = [ipaddress.ip_network(x) for x in p['DirectIp'] if not x.startswith('geoip:')]
p['DirectIp'] = [x for x in p['DirectIp'] if x.startswith('geoip:')] + [str(n) for version in (4,6) for n in ipaddress.collapse_addresses(n for n in networks if n.version==version)]

p['LastUpdated'] = str(int(time.time()))
# Publish only after all downloads, categories, ASN and country entries passed validation.
output = root/'profile.json'
temp = root/'profile.json.tmp'
temp.write_text(json.dumps(p,ensure_ascii=False,indent=2)+'\n')
check = json.loads(temp.read_text())
assert check['GlobalProxy']=='true' and check['RouteOrder']=='block-proxy-direct'
assert not any(k in check for k in ('outbounds','inbounds','servers'))
assert all(check[k] for k in ('DirectSites','DirectIp','ProxySites','BlockSites'))
assert len(json.loads((cache/'as45090.json').read_text())['data']['prefixes'])>0
temp.replace(output)
(root/'profile.json.sha256').write_text(hashlib.sha256(output.read_bytes()).hexdigest()+'\n')
print('Built standalone routing profile; no VPN server configuration. All source categories checked.')
