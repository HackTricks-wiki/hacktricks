# Expose local to the internet

{{#include ../../banners/hacktricks-training.md}}

**Στόχος αυτής της σελίδας είναι να προτείνει εναλλακτικές που επιτρέπουν τουλάχιστον την έκθεση τοπικών raw TCP ports και τοπικών webs (HTTP) στο internet ΧΩΡΙΣ να χρειάζεται να εγκατασταθεί οτιδήποτε στον άλλο server (μόνο τοπικά, αν χρειάζεται).**

## **Serveo**

Από το [https://serveo.net/](https://serveo.net/), παρέχονται δωρεάν αρκετές δυνατότητες http και port forwarding.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Από το [https://www.socketxp.com/download](https://www.socketxp.com/download), επιτρέπει την έκθεση των tcp και http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Από το [https://ngrok.com/](https://ngrok.com/), επιτρέπει την έκθεση των θυρών http και tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Από το [https://telebit.cloud/](https://telebit.cloud/) μπορείτε να εκθέσετε θύρες http και tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Από το [https://localxpose.io/](https://localxpose.io/), είναι διαθέσιμες several δυνατότητες http και port forwarding **δωρεάν**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Από το [https://expose.dev/](https://expose.dev/) μπορείς να εκθέσεις θύρες http και tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Από το [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) μπορείτε να εκθέσετε http δωρεάν:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Το CLI `cloudflared` της Cloudflare μπορεί να δημιουργήσει μη αυθεντικοποιημένα "Quick" tunnels για γρήγορα demos ή named tunnels συνδεδεμένα με το δικό σας domain/hostnames. Υποστηρίζει reverse proxies HTTP(S), καθώς και raw TCP mappings που δρομολογούνται μέσω του edge της Cloudflare.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels σάς επιτρέπουν να ορίσετε πολλαπλούς κανόνες ingress (HTTP, SSH, RDP κ.λπ.) μέσα στο `tunnel.yml`, υποστηρίζουν πολιτικές πρόσβασης ανά υπηρεσία μέσω του Cloudflare Access και μπορούν να εκτελούνται ως systemd containers για persistence. Τα Quick Tunnels είναι anonymous και ephemeral — ιδανικά για phishing payload staging ή δοκιμές webhook, αλλά το Cloudflare δεν εγγυάται uptime.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Το Tailscale v1.52+ παρέχει τις ενοποιημένες ροές εργασίας `tailscale serve` (κοινή χρήση μέσα στο tailnet) και `tailscale funnel` (δημοσίευση στο ευρύτερο internet). Και οι δύο εντολές μπορούν να λειτουργήσουν ως reverse proxy για HTTP(S) ή να προωθήσουν raw TCP, με automatic TLS και σύντομα hostnames `*.ts.net`.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Χρησιμοποιήστε το `--bg` για να αποθηκεύσετε τη διαμόρφωση χωρίς να διατηρείτε μια διεργασία στο προσκήνιο και το `tailscale funnel status` για να ελέγχετε ποιες υπηρεσίες είναι προσβάσιμες από το δημόσιο internet. Επειδή το Funnel τερματίζει το TLS στον τοπικό κόμβο, τυχόν prompts για credentials, headers ή επιβολή mTLS μπορούν να παραμείνουν υπό τον έλεγχό σας.

## Fast Reverse Proxy (frp)

Το `frp` είναι μια self-hosted επιλογή, όπου ελέγχετε τον server rendezvous (`frps`) και τον client (`frpc`). Είναι ιδανικό για red teams που διαθέτουν ήδη ένα VPS και θέλουν deterministic domains/ports.

<details>
<summary>Δείγμα διαμόρφωσης frps/frpc</summary>
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

Οι πρόσφατες εκδόσεις προσθέτουν QUIC transport, token/OIDC auth, όρια bandwidth, health checks και αντιστοιχίσεις range βασισμένες σε Go templates—χρήσιμα για τη γρήγορη δημιουργία πολλαπλών listeners που αντιστοιχούν σε implants σε διαφορετικούς hosts.<sup>[[4]](#references)</sup>

## Pinggy (βασισμένο σε SSH)

Το Pinggy παρέχει SSH-accessible tunnels μέσω TCP/443, επομένως λειτουργεί ακόμη και πίσω από captive proxies που επιτρέπουν μόνο HTTPS. Οι συνεδρίες διαρκούν 60 λεπτά στο free tier και μπορούν να γίνουν script για γρήγορα demos ή webhook relays.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Μπορείτε να ζητήσετε custom domains και tunnels μεγαλύτερης διάρκειας στο paid tier ή να ανακυκλώνετε αυτόματα τα tunnels, περικλείοντας την εντολή σε έναν βρόχο.

## Σημειώσεις Threat intel & OPSEC

Οι adversaries κάνουν όλο και μεγαλύτερη κατάχρηση του ephemeral tunneling (ιδιαίτερα των unauthenticated endpoints `trycloudflare.com` του Cloudflare) για να κάνουν staging σε payloads Remote Access Trojan και να αποκρύπτουν την υποδομή C2. Η Proofpoint παρακολουθεί campaigns από τον Φεβρουάριο του 2024, οι οποίες διέθεταν AsyncRAT, Xworm, VenomRAT, GuLoader και Remcos, κατευθύνοντας τα download stages σε βραχύβια TryCloudflare URLs, καθιστώντας τις παραδοσιακές static blocklists πολύ λιγότερο αποτελεσματικές. Εξετάστε το ενδεχόμενο να κάνετε proactive rotation των tunnels και των domains, αλλά επίσης να παρακολουθείτε για ενδεικτικά external DNS lookups προς τον tunneler που χρησιμοποιείτε, ώστε να εντοπίζετε έγκαιρα detection από blue-team ή απόπειρες αποκλεισμού της υποδομής.<sup>[[2]](#references)</sup>

## References

- [1] [Cloudflare Docs - Δημιουργία locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor κάνει κατάχρηση των Cloudflare Tunnels για τη διανομή RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Επαναφορά των Serve και Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Repository του Fast Reverse Proxy](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Χρήση](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
