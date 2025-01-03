# Izložite lokalno internetu

{{#include ../../banners/hacktricks-training.md}}

**Cilj ove stranice je da predloži alternative koje omogućavaju DA BAR izlože lokalne sirove TCP portove i lokalne web stranice (HTTP) internetu BEZ potrebe za instalacijom bilo čega na drugom serveru (samo lokalno ako je potrebno).**

## **Serveo**

Sa [https://serveo.net/](https://serveo.net/), omogućava nekoliko http i port forwarding funkcija **besplatno**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Sa [https://www.socketxp.com/download](https://www.socketxp.com/download), omogućava izlaganje tcp i http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Sa [https://ngrok.com/](https://ngrok.com/), omogućava izlaganje http i tcp portova:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Sa [https://telebit.cloud/](https://telebit.cloud/) omogućava izlaganje http i tcp portova:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Sa [https://localxpose.io/](https://localxpose.io/), omogućava nekoliko http i port forwarding funkcija **besplatno**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Sa [https://expose.dev/](https://expose.dev/) omogućava izlaganje http i tcp portova:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Sa [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) omogućava izlaganje http-a besplatno:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
