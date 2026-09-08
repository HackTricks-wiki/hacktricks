# Authorized Adversary-Emulation Labs

{{#include ../banners/hacktricks-training.md}}

These exercises reproduce **observable architecture**, not unauthorized compromise. Run them on a dedicated Linux lab host with Docker, no sensitive credentials and no route to third-party targets. The names are fixed so teardown is explicit.

{% hint style="danger" %}
Do not replace the owned containers, APs, routers, accounts or synthetic transactions below with public proxies, a neighbor's Wi-Fi, a production CDN tenant you do not control, or real illicit funds. Written authorization must cover every system and radio environment.
{% endhint %}

## Lab 1: owned ORB and redirector chain

**Objective:** show that a target records only the exit while each relay sees adjacent hops. This emulates T1090.003/T1584 structure without compromised devices.

**Requirements:** Docker Engine and unused container names beginning `ht-orb-`.

### Build

```bash
docker network create ht-orb-entry
docker network create ht-orb-transit
docker network create ht-orb-target

docker run -d --name ht-orb-target --network ht-orb-target nginx:alpine

docker run -d --name ht-orb-r2 --network ht-orb-transit \
  alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-target:80
docker network connect ht-orb-target ht-orb-r2

docker run -d --name ht-orb-r1 --network ht-orb-entry \
  alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-r2:8080
docker network connect ht-orb-transit ht-orb-r1

docker run --rm --network ht-orb-entry curlimages/curl:latest \
  -sS http://ht-orb-r1:8080/ >/dev/null
```

### Verify the visibility boundaries

```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
  ht-orb-r1 ht-orb-r2 ht-orb-target
```

Expected result: Nginx records the `ht-orb-r2` address on `ht-orb-target`, not the one-shot client. Relay logs show connections only from their adjacent network. Docker control-plane inspection still reconstructs the entire path—analogous to provider/controller evidence.

### Detection experiments

1. Repeat requests every 60 seconds and graph inter-arrival time and bytes.
2. Replace `ht-orb-r2` with a new named container/address but keep the same cadence and application request; confirm an IP-only rule loses the chain while behavior still links it.
3. Capture on the three Docker bridges with `tcpdump` on the lab host and compare timestamps.
4. Stop `ht-orb-r2`; verify there is no direct fallback from entry to target.

### Teardown

```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```

## Lab 2: SNI/Host mismatch and redirector logging

**Objective:** reproduce the routing primitive behind domain fronting on a private local edge and show where it is visible. No public CDN is involved.

### Build a local TLS edge

```bash
ht_front_dir="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=front.lab' \
  -keyout "$ht_front_dir/key.pem" -out "$ht_front_dir/cert.pem"

cat >"$ht_front_dir/default.conf" <<'EOF'
log_format routing '$remote_addr sni=$ssl_server_name host=$host request="$request"';
server {
    listen 443 ssl;
    server_name front.lab;
    ssl_certificate /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    access_log /var/log/nginx/access.log routing;
    location / {
        if ($host != origin.lab) { return 404; }
        proxy_pass http://ht-front-target:80;
    }
}
EOF

docker network create ht-front-net
docker run -d --name ht-front-target --network ht-front-net nginx:alpine
docker run -d --name ht-front-edge --network ht-front-net -p 127.0.0.1:8443:443 \
  -v "$ht_front_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$ht_front_dir:/etc/nginx/tls:ro" nginx:alpine
```

### Send and observe the mismatch

```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
  -H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```

Expected log fields include `sni=front.lab host=origin.lab`. The client-to-edge packet capture exposes SNI unless ECH is in use; the HTTP Host is encrypted on that link. The terminating edge sees both.

Now send a normal request and confirm the policy rejects it:

```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```

### Detection assertion

Alert on `sni != host` only after normalizing ports/case and checking known reverse-proxy exceptions. Add process and tenant/origin context before assigning severity.

### Teardown

```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```

## Lab 3: fast-flux DNS telemetry

**Objective:** generate a safe low-TTL/multi-ASN-like DNS dataset and validate an analytic. The returned RFC 5737 documentation addresses are non-routable for this purpose.

### Run an authoritative server

```bash
ht_dns_dir="$(mktemp -d)"
cat >"$ht_dns_dir/Corefile" <<'EOF'
.:53 {
    log
    errors
    file /zones/db.lab lab
}
EOF

mkdir -p "$ht_dns_dir/zones"
cat >"$ht_dns_dir/zones/db.lab" <<'EOF'
$ORIGIN lab.
@ 60 IN SOA ns.lab. hostmaster.lab. 1 60 60 60 5
@ 60 IN NS ns.lab.
ns 60 IN A 192.0.2.53
flux 5 IN A 192.0.2.10
flux 5 IN A 198.51.100.20
flux 5 IN A 203.0.113.30
EOF

docker run -d --name ht-flux-dns -p 127.0.0.1:1053:53/udp \
  -v "$ht_dns_dir/Corefile:/Corefile:ro" \
  -v "$ht_dns_dir/zones:/zones:ro" coredns/coredns:latest -conf /Corefile

for query_number in 1 2 3 4 5; do
  dig @127.0.0.1 -p 1053 flux.lab A +noall +answer
done
docker logs ht-flux-dns
```

Expected result: each answer carries three documentation IPs and a 5-second TTL. Real fast flux also rotates subsets over time; change the zone serial/addresses and restart this disposable server to create multiple epochs.

### Analytic validation

For a five-minute window, calculate `median(TTL)`, distinct answers, distinct synthetic ASN/geography labels and answer churn. Require at least two suspicious dimensions plus a process/follow-on event. Run the same analytic against a known CDN sample to measure false positives.

### Teardown

```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```

## Lab 4: nearest-neighbor wireless pivot

**Objective:** reproduce the APT28 boundary mismatch with two owned “organizations.” Because Wi-Fi hardware/driver commands vary, this lab specifies verifiable roles and evidence rather than pretending one `hostapd` command fits every radio.

### Equipment

- two APs you own, on isolated lab channels/SSIDs `HT-NEIGHBOR` and `HT-TARGET`;
- one target service reachable only from `HT-TARGET`;
- one dual-radio Linux pivot you own, capable of associating to both APs;
- one remote-control workstation behind `HT-NEIGHBOR`;
- RADIUS/NAC or AP association logs, DHCP logs and pivot audit/process logs.

### Procedure

1. Physically isolate or attenuate the setup so neither SSID escapes the authorized area. Confirm with a survey.
2. Configure `HT-TARGET` with an exercise identity and deliberately omit device-certificate/posture validation for the first run. Record this as the condition under test.
3. Join the pivot's first interface to `HT-NEIGHBOR` and second interface to `HT-TARGET`. Do **not** enable a general bridge; allow only the target service/port through a host firewall.
4. From the workstation, open an authenticated tunnel to the pivot and request the target service through it.
5. Record the pivot process/interface creation, both AP associations, target RADIUS event, DHCP lease and target source address.
6. Ask the detection team to reconstruct the chain without the controller map.
7. Enable EAP-TLS/managed-device posture on `HT-TARGET`, remove the pivot's approved target certificate and repeat. Access should fail at admission.
8. Repeat with a first-seen randomized MAC. Verify the certificate/device decision still works and no rule treats the MAC alone as identity.

### Success criteria

- The target initially sees a local Wi-Fi client rather than the workstation.
- Joined telemetry identifies one pivot with simultaneous neighbor-control and target-radio paths.
- Certificate/device-backed admission blocks the second run.
- No packet reaches a network outside the isolated lab.

## Lab 5: dead-drop resolver sequence

**Objective:** detect a process reading a legitimate-looking object, decoding a pointer and immediately contacting a second service.

### Build

```bash
docker network create ht-ddr-net
docker run -d --name ht-ddr-c2 --network ht-ddr-net nginx:alpine

docker run -d --name ht-ddr-web --network ht-ddr-net python:3-alpine \
  sh -c 'mkdir -p /srv && printf aHR0cDovL2h0LWRkci1jMjo4MC8= > /srv/profile.txt && python -m http.server 8000 -d /srv'

docker run --rm --name ht-ddr-client --network ht-ddr-net python:3-alpine \
  python -c 'import base64,urllib.request; p=urllib.request.urlopen("http://ht-ddr-web:8000/profile.txt").read(); u=base64.b64decode(p).decode(); print(urllib.request.urlopen(u).status)'

docker logs ht-ddr-web
docker logs ht-ddr-c2
```

The encoded content is `http://ht-ddr-c2:80/`. A working detection joins the same short-lived process/container reading `/profile.txt`, decoding content and contacting `ht-ddr-c2` within seconds. Hash and preserve the object response.

### Teardown

```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```

## Lab 6: synthetic peel-chain and bridge graph

**Objective:** practice value tracing without real assets, accounts or services.

### Create and trace the dataset

```bash
ht_graph_dir="$(mktemp -d)"
cat >"$ht_graph_dir/edges.csv" <<'EOF'
time,chain,source,destination,amount,label
10:00,A,theft,a1,100,source
10:10,A,a1,shop1,3,payment
10:10,A,a1,a2,96.9,change
10:20,A,a2,shop2,4,payment
10:20,A,a2,a3,92.8,change
10:30,A,a3,bridge_in,90,bridge_deposit
10:36,X,bridge_in,bridge_out,89.5,bridge_link_inference
10:36,B,bridge_out,b1,89.5,bridge_withdrawal
10:50,B,b1,exchange,89,service_deposit
EOF

python3 - "$ht_graph_dir/edges.csv" <<'PY'
import csv, sys
edges = list(csv.DictReader(open(sys.argv[1], newline="")))
frontier, seen = {"theft"}, set()
while frontier:
    src = frontier.pop()
    for e in edges:
        if e["source"] == src and (src, e["destination"]) not in seen:
            seen.add((src, e["destination"]))
            print(f'{e["time"]} {e["chain"]}: {src} -> {e["destination"]} {e["amount"]} [{e["label"]}]')
            frontier.add(e["destination"])
PY
```

Analysts should identify the peel/change pattern, treat the bridge link as a separately supported inference, calculate the fee/value difference, and mark the exchange as an off-chain evidence request. Change one value/time and document how confidence changes.

### Teardown

```bash
rm -rf -- "$ht_graph_dir"
```

## Lab 7: passive traffic-signaling sensor

**Objective:** emulate the network signature of a passive, magic-value-activated implant without creating a shell, persistence or remote access. The listener binds only to loopback and records a benign event.

```bash
ht_signal_dir="$(mktemp -d)"
cat >"$ht_signal_dir/listener.py" <<'PY'
import hmac, socket

token = b"HT-LAB-ACTIVATE"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 45679))
for _ in range(2):
    data, peer = sock.recvfrom(1024)
    if hmac.compare_digest(data, token):
        print(f"authorized lab activation from {peer[0]}", flush=True)
PY

python3 "$ht_signal_dir/listener.py" >"$ht_signal_dir/events.log" &
ht_signal_pid=$!
sleep 1

python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"ordinary-traffic", ("127.0.0.1", 45679))
s.sendto(b"HT-LAB-ACTIVATE", ("127.0.0.1", 45679))
PY

wait "$ht_signal_pid"
cat "$ht_signal_dir/events.log"
rm -rf -- "$ht_signal_dir"
```

Expected result: ordinary traffic produces no application event; only the designated token does. Capture loopback traffic during the run and verify a network sensor can still see both datagrams. Then evaluate host controls that detect an unexpected long-running packet listener or packet-capture filter. Real RedPenguin passive implants inspected traffic on a router and offered dangerous functionality; this lab deliberately does neither.

## Exercise report template

For every lab record:

- authorization and isolated scope;
- hypothesis and ATT&CK technique;
- topology and observer table;
- exact start/end time and configuration hashes;
- expected events per sensor;
- events actually observed and retention gaps;
- analytic logic, threshold and false-positive sample;
- whether the target team reconstructed the path;
- mitigation retest result; and
- teardown/recovery evidence.

An exercise is incomplete until the detection is rerun after mitigation and every lab resource is removed.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
