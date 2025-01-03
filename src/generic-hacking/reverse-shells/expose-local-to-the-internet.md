# Lokale Exposition zum Internet

{{#include ../../banners/hacktricks-training.md}}

**Das Ziel dieser Seite ist es, Alternativen vorzuschlagen, die es ermöglichen, MINDESTENS lokale rohe TCP-Ports und lokale Webs (HTTP) ohne die Notwendigkeit, etwas auf dem anderen Server zu installieren (nur lokal, falls erforderlich), ins Internet zu exponieren.**

## **Serveo**

Von [https://serveo.net/](https://serveo.net/), es bietet mehrere HTTP- und Port-Weiterleitungsfunktionen **kostenlos** an.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Von [https://www.socketxp.com/download](https://www.socketxp.com/download) ermöglicht es, tcp und http freizugeben:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Von [https://ngrok.com/](https://ngrok.com/) ermöglicht es, http- und tcp-Ports freizugeben:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Von [https://telebit.cloud/](https://telebit.cloud/) ermöglicht es, http- und tcp-Ports freizugeben:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Von [https://localxpose.io/](https://localxpose.io/) ermöglicht es mehrere HTTP- und Port-Weiterleitungsfunktionen **kostenlos**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Von [https://expose.dev/](https://expose.dev/) ermöglicht es, HTTP- und TCP-Ports freizugeben:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Von [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) ermöglicht es, http kostenlos freizugeben:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
