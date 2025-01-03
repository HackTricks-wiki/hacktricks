# Esporre locale a Internet

{{#include ../../banners/hacktricks-training.md}}

**L'obiettivo di questa pagina è proporre alternative che consentano ALMENO di esporre porte TCP locali e web locali (HTTP) a Internet SENZA la necessità di installare nulla nell'altro server (solo in locale se necessario).**

## **Serveo**

Da [https://serveo.net/](https://serveo.net/), consente diverse funzionalità di forwarding http e porte **gratuitamente**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Da [https://www.socketxp.com/download](https://www.socketxp.com/download), consente di esporre tcp e http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Da [https://ngrok.com/](https://ngrok.com/), consente di esporre porte http e tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Da [https://telebit.cloud/](https://telebit.cloud/) consente di esporre porte http e tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Da [https://localxpose.io/](https://localxpose.io/), consente diverse funzionalità di forwarding http e porte **gratuitamente**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Da [https://expose.dev/](https://expose.dev/) consente di esporre porte http e tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Da [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) consente di esporre http gratuitamente:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
