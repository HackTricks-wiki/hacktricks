# Expose local to the internet

{{#include ../../banners/hacktricks-training.md}}

**Bu sayfanın amacı, EN AZINDAN yerel ham TCP portlarını ve yerel webleri (HTTP) internete açmaya olanak tanıyan alternatifler önermektir, DİĞER sunucuda hiçbir şey yüklemeye gerek kalmadan (gerekirse yalnızca yerelde).**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), it allows several http and port forwarding features **for free**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download) adresinden, tcp ve http'yi açığa çıkarmaya olanak tanır:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) adresinden, http ve tcp portlarını açmanıza olanak tanır:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) adresinden http ve tcp portlarını açmanıza olanak tanır:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/) adresinden, birkaç http ve port yönlendirme özelliğini **ücretsiz** olarak sunar.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

From [https://expose.dev/](https://expose.dev/) http ve tcp portlarını açmanıza olanak tanır:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) adresinden, http'yi ücretsiz olarak açığa çıkarmaya olanak tanır:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
