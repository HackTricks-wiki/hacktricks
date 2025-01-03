# Expose local to the internet

{{#include ../../banners/hacktricks-training.md}}

**Celem tej strony jest zaproponowanie alternatyw, które pozwalają przynajmniej na wystawienie lokalnych surowych portów TCP i lokalnych stron (HTTP) do internetu BEZ potrzeby instalowania czegokolwiek na drugim serwerze (tylko lokalnie, jeśli to konieczne).**

## **Serveo**

Z [https://serveo.net/](https://serveo.net/), umożliwia kilka funkcji przekierowywania http i portów **za darmo**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Z [https://www.socketxp.com/download](https://www.socketxp.com/download) umożliwia wystawienie tcp i http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Z [https://ngrok.com/](https://ngrok.com/) pozwala na wystawienie portów http i tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Z [https://telebit.cloud/](https://telebit.cloud/) pozwala na udostępnienie portów http i tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Z [https://localxpose.io/](https://localxpose.io/) oferuje kilka funkcji przekazywania http i portów **za darmo**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Z [https://expose.dev/](https://expose.dev/) można udostępniać porty http i tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Z [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) pozwala na darmowe udostępnienie http:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
