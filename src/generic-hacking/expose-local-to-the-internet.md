# Έκθεση τοπικών υπηρεσιών στο διαδίκτυο

{{#include ../banners/hacktricks-training.md}}

**Στόχος αυτής της σελίδας είναι να προτείνει εναλλακτικές που επιτρέπουν, ΤΟΥΛΑΧΙΣΤΟΝ, την έκθεση τοπικών raw TCP ports και τοπικών ιστοτόπων (HTTP) στο διαδίκτυο, ΧΩΡΙΣ να απαιτείται εγκατάσταση οτιδήποτε στον άλλο server (μόνο τοπικά, αν χρειάζεται).**

## **Serveo**

Η τεκμηρίωση του Serveo περιγράφει την προώθηση SSH για HTTP endpoints και την ιδιωτική/δημόσια προώθηση TCP· για να ζητήσετε δημόσια TCP port διαφορετική από τις 80/443 (συμπεριλαμβανομένου του port 0 για τυχαία port), απαιτείται εγγεγραμμένος χρήστης.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Ο οδηγός έναρξης του SocketXP τεκμηριώνει τις εντολές `socketxp connect tcp://localhost:22` και `socketxp connect http://localhost:8080` για σήραγγες TCP και HTTP· ο agent αυθεντικοποιείται πρώτα με ένα token του portal.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

Το CLI του ngrok τεκμηριώνει HTTP και TCP tunnels· το FAQ του αναφέρει ότι τα TCP endpoints στο δωρεάν πακέτο απαιτούν έγκυρο τρόπο πληρωμής και ότι η κάρτα δεν χρεώνεται.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Η παλαιότερη βοήθεια CLI του Telebit.js τεκμηριώνει την εντολή `telebit http <port>` για προώθηση HTTPS και την `telebit tcp <local> [remote]` για raw TCP· η διαθεσιμότητα εξαρτάται από την ανάπτυξη και το relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Η τρέχουσα ιστοσελίδα του LocalXpose τεκμηριώνει την εντολή `loclx tunnel http --to 3000`, αναφέρει υποστήριξη HTTP/TLS/TCP/UDP και δηλώνει ότι το δωρεάν πρόγραμμα καλύπτει προσωπική/ελαφριά εμπορική χρήση, ενώ η διοχέτευση TCP είναι διαθέσιμη μόνο σε επί πληρωμή πρόγραμμα.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Το Expose τεκμηριώνει την εντολή `expose share` για τοπικά URL HTTP/HTTPS και την εντολή `expose share-port`, η οποία είναι διαθέσιμη μόνο στο PRO, για θύρες TCP.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Το επίσημο repository του localtunnel περιγράφει πώς να εκθέσετε το localhost για δοκιμές και τεκμηριώνει την παρακάτω εντολή NPX.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Η τρέχουσα τεκμηρίωση της Cloudflare παρουσιάζει μη πιστοποιημένα «Quick» tunnels για τοπική ανάπτυξη, ενώ η επισκόπηση του προϊόντος αναφέρει τα HTTP, HTTPS, TCP, SSH και RDP μεταξύ των υποστηριζόμενων published protocols.<sup>[[11]](#references)[[12]](#references)</sup>

Για ένα επώνυμο tunnel που διαχειρίζεται τοπικά, η Cloudflare τεκμηριώνει τη ροή εργασίας `tunnel login`, `create`, `route dns` και `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Τα Named Tunnels μπορούν να ορίζουν πολλούς κανόνες εισερχόμενης κίνησης σε YAML· οι πολιτικές του Cloudflare Access μπορούν να ελέγχουν την πρόσβαση σε δημοσιευμένες εφαρμογές, ενώ το Cloudflare τεκμηριώνει διαδρομές ανάπτυξης με service και Docker για την εκτέλεση connectors. Τα Quick Tunnels είναι ανώνυμα, προσωρινά tunnels για δοκιμές, με όριο 200 ταυτόχρονων αιτημάτων και χωρίς υποστήριξη Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Το τρέχον CLI του Tailscale χρησιμοποιεί το Serve για κοινή χρήση μόνο εντός του tailnet και το Funnel για δημόσια κοινή χρήση. Οι εντολές υποστηρίζουν προορισμούς HTTP/HTTPS reverse proxy και προώθηση TCP· η ακατέργαστη λειτουργία TCP του Funnel περιορίζεται στις θύρες 443, 8443 και 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Χρησιμοποιήστε το `--bg` για να διατηρήσετε τη ρύθμιση χωρίς να παραμένει ενεργή μια διεργασία στο προσκήνιο και χρησιμοποιήστε το `tailscale funnel status` για να ελέγξετε ποιες υπηρεσίες είναι προσβάσιμες από το δημόσιο internet. Για στόχους HTTPS Funnel, η τεκμηρίωση του Tailscale αναφέρει ότι το TLS τερματίζεται στον τοπικό κόμβο πριν προωθηθεί το αίτημα στην τοπική υπηρεσία.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

Το `frp` είναι μια επιλογή self-hosted, όπου ελέγχετε τον διακομιστή rendezvous (`frps`) και τον client (`frpc`). Η τεκμηρίωσή του καλύπτει την προώθηση τοπικών υπηρεσιών πίσω από NAT ή firewall, με προκαθορισμένες απομακρυσμένες θύρες ή domains.<sup>[[20]](#references)</sup>

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

Η τεκμηρίωση του τρέχοντος project περιλαμβάνει μεταφορά QUIC, authentication με token/OIDC, όρια bandwidth, health checks και αντιστοιχίσεις range σε Go-template — συμβουλευτείτε την έκδοση που αντιστοιχεί στην εγκατάστασή σας πριν χρησιμοποιήσετε οποιαδήποτε από αυτές τις επιλογές.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Το Pinggy τεκμηριώνει reverse forwarding μέσω SSH στη θύρα 443, οπότε μπορεί να λειτουργήσει σε δίκτυα όπου είναι αποκλεισμένο το εξερχόμενο SSH στη θύρα 22. Το δωρεάν πρόγραμμα τερματίζεται μετά από 60 λεπτά και χρησιμοποιεί νέο URL μετά την επανασύνδεση, ενώ το Pro προσφέρει persistent tunnels και custom domains.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Μπορείτε να ζητήσετε custom domains και persistent tunnels στο Pro.<sup>[[22]](#references)</sup> Μπορείτε να ανακυκλώνετε αυτόματα προσωρινά tunnels, περικλείοντας την εντολή σε έναν βρόχο.

## Σημειώσεις threat intel & OPSEC

Οι αντίπαλοι έχουν καταχραστεί ephemeral tunneling, συμπεριλαμβανομένων των unauthenticated endpoints `trycloudflare.com` της Cloudflare, για να παραδίδουν Remote Access Trojans μέσω προσωρινής υποδομής. Η Proofpoint ανέφερε δραστηριότητα που παρατηρήθηκε για πρώτη φορά τον Φεβρουάριο του 2024, η οποία αφορούσε τα Xworm, AsyncRAT, VenomRAT, GuLoader και Remcos, και σημείωσε ότι τα προσωρινά tunnels δυσχεραίνουν τις άμυνες που βασίζονται σε static blocklists.<sup>[[23]](#references)</sup> Εξετάστε το ενδεχόμενο να αλλάζετε προληπτικά tunnels και domains, και να παρακολουθείτε για χαρακτηριστικά εξωτερικά DNS lookups προς το tunneler που χρησιμοποιείτε, ώστε να εντοπίζετε έγκαιρα πιθανή ανίχνευση από την blue team ή απόπειρες αποκλεισμού της υποδομής.

## References

- [1] [Τεκμηρίωση Serveo](https://serveo.net/docs/)
- [2] [Τεκμηρίωση SocketXP - Ξεκινώντας](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Διεπαφή γραμμής εντολών του ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [Συχνές ερωτήσεις για το ngrok](https://ngrok.com/docs/faq)
- [5] [Βοήθεια παλαιού CLI του Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Τεκμηρίωση LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Κοινή χρήση ιστοτόπων](https://expose.dev/docs/client/sharing)
- [9] [Expose - Κοινή χρήση θυρών TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Αποθετήριο localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Έγγραφα Cloudflare - Ρύθμιση του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Επισκόπηση Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Έγγραφα Cloudflare - Χρήσιμες εντολές tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Έγγραφα Cloudflare - Δρομολόγηση](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Έγγραφα Cloudflare - Αρχείο ρυθμίσεων](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Πολιτικές Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Έγγραφα Cloudflare - Παράμετροι εκτέλεσης](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Εντολή Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Εντολή Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Αποθετήριο Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Τεκμηρίωση Pinggy - Χρήση](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Απλά localhost tunnels](https://pinggy.io/)
- [23] [Proofpoint - Παράγοντας απειλής καταχράται τα Cloudflare Tunnels για την παράδοση RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
