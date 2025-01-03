# Expose local to the internet

{{#include ../../banners/hacktricks-training.md}}

**Lengo la ukurasa huu ni kupendekeza mbadala ambazo zinaruhusu KIASI KIDOGO kufichua bandari za TCP za ndani na wavuti za ndani (HTTP) kwa mtandao BILA kuhitaji kufunga chochote kwenye seva nyingine (tu kwenye ndani ikiwa inahitajika).**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), it allows several http and port forwarding features **for free**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Kutoka [https://www.socketxp.com/download](https://www.socketxp.com/download), inaruhusu kufichua tcp na http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Kutoka [https://ngrok.com/](https://ngrok.com/), inaruhusu kufichua port za http na tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Kutoka [https://telebit.cloud/](https://telebit.cloud/) inaruhusu kufichua port za http na tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Kutoka [https://localxpose.io/](https://localxpose.io/), inaruhusu vipengele kadhaa vya http na upitishaji wa bandari **bila malipo**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

From [https://expose.dev/](https://expose.dev/) inaruhusu kufichua port za http na tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Kutoka [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) inaruhusu kufichua http bure:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
