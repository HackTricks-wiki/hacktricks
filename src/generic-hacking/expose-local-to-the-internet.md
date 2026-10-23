# Έκθεση του τοπικού περιβάλλοντος στο internet

{{#include ../banners/hacktricks-training.md}}

**Στόχος αυτής της σελίδας είναι να προτείνει εναλλακτικές που επιτρέπουν τουλάχιστον την έκθεση τοπικών raw TCP ports και τοπικών ιστοσελίδων (HTTP) στο internet, ΧΩΡΙΣ να χρειάζεται να εγκαταστήσετε οτιδήποτε στον άλλο server (μόνο τοπικά, αν χρειάζεται).**

Για προώθηση μεταξύ hosts αντί για δημοσίευση μιας υπηρεσίας μέσω δημόσιου relay, δείτε το [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md).

## **Serveo**

Η τεκμηρίωση του Serveo περιγράφει SSH forwarding για HTTP endpoints και ιδιωτικό/δημόσιο TCP forwarding. Η θύρα `0` ζητά τυχαία δημόσια TCP port, ακόμη και για ανώνυμες συνεδρίες, αλλά αυτές οι συνεδρίες έχουν σύντομα χρονικά όρια και όρια συνδέσεων· η αίτηση συγκεκριμένης δημόσιας TCP port απαιτεί λογαριασμό επί πληρωμή.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Ο οδηγός έναρξης του SocketXP περιγράφει τις εντολές `socketxp connect tcp://localhost:22` και `socketxp connect http://localhost:8080` για TCP και HTTP tunnels· ο agent αυθεντικοποιείται πρώτα με token του portal.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

Το CLI του ngrok τεκμηριώνει HTTP και TCP tunnels. Τα TCP endpoints απαιτούν μια δεσμευμένη διεύθυνση TCP στον λογαριασμό· το δωρεάν πρόγραμμα απαιτεί επίσης έναν έγκυρο τρόπο πληρωμής, για τον οποίο το FAQ αναφέρει ότι δεν χρεώνεται.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Η παλαιότερη τεκμηρίωση βοήθειας του Telebit.js CLI περιγράφει την εντολή `telebit http <port>` για προώθηση HTTPS και την `telebit tcp <local> [remote]` για ακατέργαστο TCP· η διαθεσιμότητα εξαρτάται από την ανάπτυξη και το relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Ο τρέχων ιστότοπος του LocalXpose τεκμηριώνει την εντολή `loclx tunnel http --to 3000`, αναφέρει υποστήριξη HTTP/TLS/TCP/UDP και σημειώνει ότι το δωρεάν πρόγραμμα καλύπτει προσωπική/ελαφριά εμπορική χρήση, ενώ η δημιουργία TCP tunnel είναι διαθέσιμη μόνο σε επί πληρωμή πρόγραμμα.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Το Expose τεκμηριώνει την εντολή `expose share` για τοπικά URL HTTP/HTTPS και μια εντολή `expose share-port`, διαθέσιμη μόνο στην έκδοση PRO, για θύρες TCP.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Το επίσημο αποθετήριο του localtunnel περιγράφει πώς να εκθέσετε το localhost για δοκιμές και τεκμηριώνει την παρακάτω εντολή NPX.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Η τρέχουσα τεκμηρίωση της Cloudflare παρουσιάζει μη επαληθευμένα tunnels «Quick» για τοπική ανάπτυξη, ενώ η επισκόπηση του προϊόντος αναφέρει τα HTTP, HTTPS, TCP, SSH και RDP μεταξύ των υποστηριζόμενων πρωτοκόλλων που μπορούν να δημοσιευτούν.<sup>[[11]](#references)[[12]](#references)</sup> Σε αντίθεση με τα HTTP(S), οι δημοσιευμένες διαδρομές TCP, SSH και RDP δεν είναι άμεσα προσβάσιμες με ένα τυπικό client: η Cloudflare απαιτεί το `cloudflared` στον client που συνδέεται, επομένως αυτές οι διαδρομές δεν πληρούν την απαίτηση αυτής της σελίδας να μην απαιτείται εγκατάσταση client για raw TCP.<sup>[[24]](#references)</sup>

Για ένα ονομαστικό tunnel που διαχειρίζεται τοπικά, η Cloudflare τεκμηριώνει τη ροή εργασιών `tunnel login`, `create`, `route dns` και `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Τα Named tunnels μπορούν να ορίζουν πολλαπλούς κανόνες ingress σε YAML· οι πολιτικές Cloudflare Access μπορούν να ελέγχουν την πρόσβαση σε δημοσιευμένες εφαρμογές, ενώ η Cloudflare τεκμηριώνει τις επιλογές ανάπτυξης μέσω service και Docker για την εκτέλεση connectors. Τα Quick Tunnels είναι ανώνυμα, προσωρινά tunnels δοκιμών, με όριο 200 ταυτόχρονων αιτημάτων και χωρίς υποστήριξη Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Το τρέχον CLI του Tailscale χρησιμοποιεί το Serve για κοινοποίηση μόνο στο tailnet και το Funnel για δημόσια κοινοποίηση. Οι εντολές υποστηρίζουν στόχους reverse proxy HTTP/HTTPS και προώθηση TCP· η raw TCP λειτουργία του Funnel περιορίζεται στις θύρες 443, 8443 και 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Χρησιμοποιήστε το `--bg` για να διατηρήσετε τη ρύθμιση χωρίς να παραμένει μια διεργασία στο προσκήνιο, και χρησιμοποιήστε το `tailscale funnel status` για να ελέγξετε ποιες υπηρεσίες είναι προσβάσιμες από το δημόσιο internet. Για στόχους HTTPS Funnel, η τεκμηρίωση του Tailscale αναφέρει ότι το TLS τερματίζεται στον τοπικό κόμβο πριν προωθηθεί το αίτημα στην τοπική υπηρεσία.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

Το `frp` είναι μια επιλογή αυτοφιλοξενίας, όπου ελέγχετε τον διακομιστή rendezvous (`frps`) και τον πελάτη (`frpc`). Η τεκμηρίωσή του καλύπτει την προώθηση τοπικών υπηρεσιών πίσω από NAT ή firewall, με ντετερμινιστικές απομακρυσμένες θύρες ή τομείς.<sup>[[20]](#references)</sup>

<details>
<summary>Δείγμα διαμόρφωσης frps/frpc</summary>

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

Η τρέχουσα τεκμηρίωση του project περιλαμβάνει μεταφορά QUIC, αυθεντικοποίηση με token/OIDC, όρια bandwidth, health checks και αντιστοιχίσεις Go-template range — συμβουλευτείτε την έκδοση που αντιστοιχεί στην εγκατάστασή σας πριν χρησιμοποιήσετε οποιαδήποτε από αυτές τις επιλογές.<sup>[[20]](#references)</sup>

## Pinggy (βασισμένο σε SSH)

Το Pinggy τεκμηριώνει την αντίστροφη προώθηση μέσω SSH στη θύρα 443, οπότε μπορεί να λειτουργήσει σε δίκτυα όπου είναι αποκλεισμένο το εξερχόμενο SSH στη θύρα 22. Το δωρεάν πρόγραμμα λήγει μετά από 60 λεπτά και χρησιμοποιεί νέα URL μετά την επανασύνδεση, ενώ το Pro προσθέτει μόνιμα tunnels και custom domains.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Μπορείτε να ζητήσετε προσαρμοσμένους τομείς και μόνιμα tunnels στο Pro.<sup>[[22]](#references)</sup> Μπορείτε να ανακυκλώνετε αυτόματα τα προσωρινά tunnels, περικλείοντας την εντολή σε έναν βρόχο.

## Σημειώσεις για Threat intel & OPSEC

Adversaries έχουν καταχραστεί εφήμερα tunneling, συμπεριλαμβανομένων των unauthenticated endpoints `trycloudflare.com` της Cloudflare, για να παραδώσουν Remote Access Trojans μέσω προσωρινής υποδομής. Η Proofpoint ανέφερε δραστηριότητα που εντοπίστηκε για πρώτη φορά τον Φεβρουάριο του 2024, η οποία περιλάμβανε τα Xworm, AsyncRAT, VenomRAT, GuLoader και Remcos, και σημείωσε ότι τα προσωρινά tunnels δυσκολεύουν τις άμυνες που βασίζονται σε static blocklists.<sup>[[23]](#references)</sup> Εξετάστε το ενδεχόμενο προληπτικής εναλλαγής tunnels και domains, καθώς και παρακολούθησης για ενδεικτικά εξωτερικά DNS lookups προς τον tunneler που χρησιμοποιείτε, ώστε να εντοπίζετε έγκαιρα την ανίχνευση από blue team ή απόπειρες αποκλεισμού της υποδομής.

## References

- [1] [Τεκμηρίωση Serveo](https://serveo.net/docs/)
- [2] [Τεκμηρίωση SocketXP - Ξεκινώντας](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Διεπαφή γραμμής εντολών του ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [Συχνές ερωτήσεις για το ngrok](https://ngrok.com/docs/faq)
- [5] [Βοήθεια CLI του παλαιού Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Τεκμηρίωση LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Κοινή χρήση ιστοτόπων](https://expose.dev/docs/client/sharing)
- [9] [Expose - Κοινή χρήση θυρών TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Αποθετήριο localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Τεκμηρίωση Cloudflare - Ρύθμιση Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Επισκόπηση του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Τεκμηρίωση Cloudflare - Χρήσιμες εντολές tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Τεκμηρίωση Cloudflare - Δρομολόγηση](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Τεκμηρίωση Cloudflare - Αρχείο ρυθμίσεων](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Πολιτικές Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Τεκμηρίωση Cloudflare - Παράμετροι εκτέλεσης](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Εντολή Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Εντολή Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Αποθετήριο fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Τεκμηρίωση Pinggy - Χρήση](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Απλά Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat actor καταχράται Cloudflare Tunnels για να παραδώσει RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Τεκμηρίωση Cloudflare - Δρομολόγηση tunnel και υποστηριζόμενα πρωτόκολλα](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
