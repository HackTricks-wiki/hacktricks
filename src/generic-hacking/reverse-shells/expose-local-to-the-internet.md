# Expose local στο internet

{{#include ../../banners/hacktricks-training.md}}

**Ο στόχος αυτής της σελίδας είναι να προτείνει εναλλακτικές που επιτρέπουν τουλάχιστον την έκθεση local raw TCP ports και local webs (HTTP) στο internet ΧΩΡΙΣ να απαιτείται η εγκατάσταση οποιουδήποτε στοιχείου στον άλλο server (μόνο στο local, αν χρειάζεται).**

## **Serveo**

Η τεκμηρίωση του Serveo περιγράφει SSH forwarding για HTTP endpoints και private/public TCP forwarding. Η αίτηση για public TCP port διαφορετικό από τα 80/443 (συμπεριλαμβανομένου του port 0 για τυχαίο port) απαιτεί εγγεγραμμένο χρήστη.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Ο οδηγός getting-started του SocketXP τεκμηριώνει τις εντολές `socketxp connect tcp://localhost:22` και `socketxp connect http://localhost:8080` για TCP και HTTP tunnels· ο agent authenticates πρώτα με ένα portal token.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Το CLI του ngrok τεκμηριώνει HTTP και TCP tunnels· το FAQ του αναφέρει ότι τα TCP endpoints του free tier απαιτούν έγκυρο payment method και ότι η κάρτα δεν χρεώνεται.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Η legacy βοήθεια του Telebit.js CLI τεκμηριώνει το `telebit http <port>` για προώθηση HTTPS και το `telebit tcp <local> [remote]` για raw TCP· η διαθεσιμότητα εξαρτάται από το deployment και το relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Ο τρέχων ιστότοπος του LocalXpose τεκμηριώνει το `loclx tunnel http --to 3000`, αναφέρει υποστήριξη για HTTP/TLS/TCP/UDP και δηλώνει ότι το δωρεάν πρόγραμμα καλύπτει προσωπική/ελαφριά εμπορική χρήση, ενώ το TCP tunneling είναι δυνατότητα επί πληρωμή.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Τα έγγραφα του Expose περιγράφουν την εντολή `expose share` για τοπικά URL HTTP/HTTPS και μια εντολή `expose share-port` μόνο για PRO για TCP ports.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Το επίσημο repository του localtunnel περιγράφει την έκθεση του localhost για testing και τεκμηριώνει την παρακάτω εντολή NPX.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Η τρέχουσα τεκμηρίωση του Cloudflare παρουσιάζει μη αυθεντικοποιημένα tunnel «Quick» για τοπική ανάπτυξη, ενώ η επισκόπηση του προϊόντος αναφέρει τα HTTP, HTTPS, TCP, SSH και RDP μεταξύ των υποστηριζόμενων δημοσιευμένων πρωτοκόλλων.<sup>[[11]](#references)[[12]](#references)</sup>

Για ένα named tunnel που διαχειρίζεται τοπικά, το Cloudflare τεκμηριώνει τη ροή εργασίας `tunnel login`, `create`, `route dns` και `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Τα named tunnels μπορούν να ορίσουν πολλαπλούς ingress rules σε YAML· οι Cloudflare Access policies μπορούν να ελέγχουν την πρόσβαση σε published applications, ενώ το Cloudflare τεκμηριώνει paths ανάπτυξης μέσω service και Docker για τη λειτουργία connectors. Τα Quick Tunnels είναι anonymous, προσωρινά testing tunnels με όριο 200 ταυτόχρονων requests και χωρίς υποστήριξη για Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Το τρέχον CLI του Tailscale χρησιμοποιεί το Serve για sharing μόνο στο tailnet και το Funnel για public sharing. Οι εντολές υποστηρίζουν HTTP/HTTPS reverse-proxy targets και TCP forwarding· το raw TCP mode του Funnel περιορίζεται στις θύρες 443, 8443 και 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Χρησιμοποίησε το `--bg` για να διατηρήσεις τη ρύθμιση χωρίς να διατηρείς μια διεργασία στο foreground και χρησιμοποίησε το `tailscale funnel status` για να ελέγχεις ποιες υπηρεσίες είναι προσβάσιμες από το public internet. Για HTTPS Funnel targets, το Tailscale τεκμηριώνει TLS termination στο local node πριν από την προώθηση του request στην local service.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

Το `frp` είναι μια self-hosted επιλογή όπου ελέγχεις τον rendezvous server (`frps`) και τον client (`frpc`). Η τεκμηρίωσή του καλύπτει την προώθηση local services πίσω από NAT ή firewall, με deterministic remote ports/domains.<sup>[[20]](#references)</sup>

<details>
<summary>Δείγμα ρύθμισης frps/frpc</summary>
```bash
# Server: start frps with its server configuration
./frps -c frps.toml

# Client: save this as frpc.toml, then start it
cat > frpc.toml <<'EOF'
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
./frpc -c frpc.toml
```
</details>

Η τρέχουσα τεκμηρίωση του project περιλαμβάνει QUIC transport, token/OIDC authentication, bandwidth limits, health checks και Go-template range mappings—συμβουλευτείτε το release που αντιστοιχεί στο deployment σας πριν χρησιμοποιήσετε οποιαδήποτε από αυτές τις options.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Το Pinggy τεκμηριώνει SSH reverse forwarding μέσω της port 443, επομένως μπορεί να λειτουργήσει σε δίκτυα όπου το outbound SSH μέσω της port 22 είναι blocked. Το free plan του τερματίζει μετά από 60 λεπτά και χρησιμοποιεί νέο URL μετά την επανασύνδεση, ενώ το Pro προσθέτει persistent tunnels και custom domains.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Μπορείτε να ζητήσετε custom domains και persistent tunnels στο Pro.<sup>[[22]](#references)</sup> Μπορείτε να ανακυκλώνετε αυτόματα τα temporary tunnels, περικλείοντας την εντολή σε έναν βρόχο.

## Πληροφορίες απειλών & σημειώσεις OPSEC

Οι adversaries έχουν κάνει κατάχρηση του ephemeral tunneling, συμπεριλαμβανομένων των unauthenticated endpoints `trycloudflare.com` του Cloudflare, για να παραδώσουν Remote Access Trojans μέσω προσωρινής υποδομής. Η Proofpoint ανέφερε δραστηριότητα που παρατηρήθηκε για πρώτη φορά τον Φεβρουάριο του 2024, η οποία περιλάμβανε τα Xworm, AsyncRAT, VenomRAT, GuLoader και Remcos, και σημείωσε ότι τα temporary tunnels περιπλέκουν τις άμυνες που βασίζονται σε static blocklists.<sup>[[23]](#references)</sup> Εξετάστε το ενδεχόμενο προληπτικής εναλλαγής tunnels και domains και παρακολουθείτε για χαρακτηριστικά external DNS lookups προς το tunneler που χρησιμοποιείτε, ώστε να εντοπίζετε έγκαιρα blue-team detection ή απόπειρες αποκλεισμού της υποδομής.

## References

- [1] [Τεκμηρίωση Serveo](https://serveo.net/docs/)
- [2] [Τεκμηρίωση SocketXP - Ξεκινώντας](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Διεπαφή γραμμής εντολών του ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [Συχνές ερωτήσεις του ngrok](https://ngrok.com/docs/faq)
- [5] [Βοήθεια legacy CLI του Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Τεκμηρίωση LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Κοινή χρήση sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - Κοινή χρήση TCP ports](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [repository localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Docs - Ρύθμιση του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Επισκόπηση του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Docs - Χρήσιμες εντολές tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Docs - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Docs - Αρχείο configuration](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Πολιτικές Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Docs - Παράμετροι εκτέλεσης](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Εντολή Serve του Tailscale](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Εντολή Funnel του Tailscale](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [repository fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Τεκμηρίωση Pinggy - Χρήση](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Απλά Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor κάνει κατάχρηση Cloudflare Tunnels για την παράδοση RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
