# Exponer local a Internet

{{#include ../../banners/hacktricks-training.md}}

**El objetivo de esta página es proponer alternativas que permitan AL MENOS exponer puertos TCP locales y webs locales (HTTP) a Internet SIN necesidad de instalar nada en el otro servidor (solo en local si es necesario).**

## **Serveo**

Desde [https://serveo.net/](https://serveo.net/), permite varias características de reenvío de http y puertos **de forma gratuita**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Desde [https://www.socketxp.com/download](https://www.socketxp.com/download), permite exponer tcp y http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Desde [https://ngrok.com/](https://ngrok.com/), permite exponer puertos http y tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Desde [https://telebit.cloud/](https://telebit.cloud/) permite exponer puertos http y tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Desde [https://localxpose.io/](https://localxpose.io/), permite varias características de reenvío de http y puertos **de forma gratuita**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Desde [https://expose.dev/](https://expose.dev/) permite exponer puertos http y tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Desde [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) permite exponer http de forma gratuita:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
