# Exposer local à Internet

{{#include ../../banners/hacktricks-training.md}}

**L'objectif de cette page est de proposer des alternatives qui permettent AU MOINS d'exposer des ports TCP bruts locaux et des webs locaux (HTTP) à Internet SANS avoir besoin d'installer quoi que ce soit sur l'autre serveur (uniquement en local si nécessaire).**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), it allows several http and port forwarding features **for free**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Depuis [https://www.socketxp.com/download](https://www.socketxp.com/download), il permet d'exposer tcp et http :
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Depuis [https://ngrok.com/](https://ngrok.com/), il permet d'exposer des ports http et tcp :
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Depuis [https://telebit.cloud/](https://telebit.cloud/), il permet d'exposer des ports http et tcp :
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Depuis [https://localxpose.io/](https://localxpose.io/), il permet plusieurs fonctionnalités de redirection http et de ports **gratuitement**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

De [https://expose.dev/](https://expose.dev/) il permet d'exposer des ports http et tcp :
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Depuis [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel), il permet d'exposer http gratuitement :
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
