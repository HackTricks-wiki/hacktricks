# Εξ expose το τοπικό στο διαδίκτυο

{{#include ../../banners/hacktricks-training.md}}

**Ο στόχος αυτής της σελίδας είναι να προτείνει εναλλακτικές που επιτρέπουν τουλάχιστον να εκθέσουν τοπικούς ακατέργαστους TCP θύρες και τοπικά webs (HTTP) στο διαδίκτυο ΧΩΡΙΣ να χρειάζεται να εγκαταστήσετε οτιδήποτε στον άλλο διακομιστή (μόνο τοπικά αν χρειαστεί).**

## **Serveo**

Από [https://serveo.net/](https://serveo.net/), επιτρέπει πολλές δυνατότητες προώθησης http και θύρας **δωρεάν**.
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

Από [https://ngrok.com/](https://ngrok.com/), επιτρέπει την έκθεση http και tcp θυρών:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Από [https://telebit.cloud/](https://telebit.cloud/) επιτρέπει την έκθεση http και tcp θυρών:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Από [https://localxpose.io/](https://localxpose.io/), επιτρέπει πολλές δυνατότητες http και προώθησης θύρας **χωρίς κόστος**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Από [https://expose.dev/](https://expose.dev/) επιτρέπει την έκθεση http και tcp θυρών:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Από [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) επιτρέπει την έκθεση http δωρεάν:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
