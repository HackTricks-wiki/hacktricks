# Expor local para a internet

{{#include ../../banners/hacktricks-training.md}}

**O objetivo desta página é propor alternativas que permitam, NO MÍNIMO, expor portas TCP brutas locais e webs locais (HTTP) para a internet SEM precisar instalar nada no outro servidor (apenas local, se necessário).**

## **Serveo**

De [https://serveo.net/](https://serveo.net/), permite vários recursos de encaminhamento de http e portas **gratuitamente**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Do [https://www.socketxp.com/download](https://www.socketxp.com/download), permite expor tcp e http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Do [https://ngrok.com/](https://ngrok.com/), permite expor portas http e tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

A partir de [https://telebit.cloud/](https://telebit.cloud/) permite expor portas http e tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Do [https://localxpose.io/](https://localxpose.io/), ele permite vários recursos de encaminhamento http e de porta **gratuitamente**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Do [https://expose.dev/](https://expose.dev/) permite expor portas http e tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Do [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) permite expor http gratuitamente:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
