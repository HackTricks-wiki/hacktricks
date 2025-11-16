# Έκθεση τοπικού στο διαδίκτυο

{{#include ../../banners/hacktricks-training.md}}

**Ο στόχος αυτής της σελίδας είναι να προτείνει εναλλακτικές που επιτρέπουν τουλάχιστον την έκθεση τοπικών raw TCP θυρών και τοπικών web (HTTP) στο διαδίκτυο χωρίς να χρειάζεται να εγκατασταθεί τίποτα στον άλλο server (μόνο τοπικά αν χρειαστεί).**

## **Serveo**

Από το [https://serveo.net/](https://serveo.net/), επιτρέπει διάφορες δυνατότητες http και προώθησης θυρών **δωρεάν**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Από [https://www.socketxp.com/download](https://www.socketxp.com/download), επιτρέπει την έκθεση tcp και http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Από [https://ngrok.com/](https://ngrok.com/), επιτρέπει την έκθεση θυρών http και tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Από [https://telebit.cloud/](https://telebit.cloud/) σας επιτρέπει να εκθέσετε θύρες http και tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Από το [https://localxpose.io/](https://localxpose.io/), προσφέρει διάφορες δυνατότητες http και port forwarding **δωρεάν**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Από το [https://expose.dev/](https://expose.dev/) μπορείτε να εκθέσετε http και tcp ports:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Από [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) σας επιτρέπει να εκθέσετε http δωρεάν:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Το CLI `cloudflared` της Cloudflare μπορεί να δημιουργήσει μη-επαληθευμένα "Quick" tunnels για γρήγορες επιδείξεις ή named tunnels δεσμευμένα στο δικό σας domain/hostnames. Υποστηρίζει HTTP(S) reverse proxies καθώς και raw TCP mappings που δρομολογούνται μέσω του Cloudflare's edge.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels σας επιτρέπουν να ορίσετε πολλαπλούς κανόνες εισόδου (HTTP, SSH, RDP, κ.λπ.) μέσα στο `tunnel.yml`, υποστηρίζουν πολιτικές πρόσβασης ανά υπηρεσία μέσω Cloudflare Access και μπορούν να τρέχουν ως systemd containers για επιμονή. Quick Tunnels είναι ανώνυμα και εφήμερα — ιδανικά για phishing payload staging ή webhook tests, αλλά η Cloudflare δεν εγγυάται uptime.

## Tailscale Funnel / Serve

Το Tailscale v1.52+ περιλαμβάνει ενοποιημένες ροές εργασίας για `tailscale serve` (share inside the tailnet) και `tailscale funnel` (publish to the wider internet). Και οι δύο εντολές μπορούν να κάνουν reverse proxy HTTP(S) ή να προωθήσουν raw TCP με αυτόματο TLS και σύντομα `*.ts.net` hostnames.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Χρησιμοποιήστε `--bg` για να διατηρήσετε τη ρύθμιση χωρίς να τρέχετε διαδικασία στο foreground, και `tailscale funnel status` για να ελέγξετε ποιες υπηρεσίες είναι προσβάσιμες από το δημόσιο διαδίκτυο. Επειδή ο Funnel τερματίζει το TLS στον τοπικό κόμβο, οποιεσδήποτε προτροπές διαπιστευτηρίων, headers ή επιβολή mTLS μπορούν να παραμείνουν υπό τον έλεγχό σας.

## Fast Reverse Proxy (frp)

`frp` είναι μια self-hosted επιλογή όπου ελέγχετε τον rendezvous server (`frps`) και τον client (`frpc`). Είναι εξαιρετικό για red teams που ήδη διαθέτουν VPS και θέλουν deterministic domains/ports.

<details>
<summary>Δείγμα frps/frpc διαμόρφωσης</summary>
```bash
# Server: bind TCP/HTTP entry points and enable dashboard
./frps -c frps.toml

# Client: forward local 22 to remote port 6000 and a web app to vhost
./frpc -c <<'EOF'
serverAddr = "c2.example.com"
serverPort = 7000

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000

[[proxies]]
name = "panel"
type = "http"
localPort = 8080
customDomains = ["panel.example.com"]
EOF
```
</details>

Οι πρόσφατες εκδόσεις προσθέτουν QUIC transport, token/OIDC auth, όρια εύρους ζώνης, ελέγχους υγείας και Go-template-based range mappings — χρήσιμα για την γρήγορη δημιουργία πολλαπλών listeners που χαρτογραφούνται πίσω σε implants σε διαφορετικούς hosts.

## Pinggy (SSH-based)

Το Pinggy παρέχει SSH-accessible tunnels πάνω από TCP/443, οπότε λειτουργεί ακόμη και πίσω από captive proxies που επιτρέπουν μόνο HTTPS. Οι συνεδρίες διαρκούν 60 λεπτά στο free tier και μπορούν να αυτοματοποιηθούν για γρήγορα demos ή webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Μπορείτε να ζητήσετε custom domains και longer-lived tunnels στο paid tier, ή να ανακυκλώνετε tunnels αυτόματα τυλίγοντας την εντολή σε ένα loop.

## Σημειώσεις Threat intel & OPSEC

Οι αντίπαλοι έχουν όλο και περισσότερο καταχραστεί το ephemeral tunneling (ειδικά τα unauthenticated endpoints του Cloudflare `trycloudflare.com`) για να αναπτύξουν Remote Access Trojan payloads και να αποκρύψουν την C2 infrastructure. Η Proofpoint παρακολούθησε εκστρατείες από τον Φεβρουάριο του 2024 που διένειμαν AsyncRAT, Xworm, VenomRAT, GuLoader και Remcos δείχνοντας τα στάδια download σε βραχύβια TryCloudflare URLs, κάνοντας τις παραδοσιακές static blocklists πολύ λιγότερο αποτελεσματικές. Σκεφτείτε να περιστρέφετε proactively tunnels και domains, αλλά επίσης παρακολουθείτε τα χαρακτηριστικά external DNS lookups προς τον tunneler που χρησιμοποιείτε, ώστε να εντοπίσετε νωρίς blue-team detection ή προσπάθειες infrastructure blocking.

## Αναφορές

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
