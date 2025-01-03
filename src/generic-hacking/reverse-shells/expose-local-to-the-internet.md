# Stel plaaslik bloot aan die internet

{{#include ../../banners/hacktricks-training.md}}

**Die doel van hierdie bladsy is om alternatiewe voor te stel wat TEN MINSTE toelaat om plaaslike rou TCP-poorte en plaaslike webwerwe (HTTP) aan die internet bloot te stel SONDER om enigiets op die ander bediener te installeer (slegs plaaslik indien nodig).**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), dit bied verskeie http en poort deurgee funksies **gratis** aan.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Van [https://www.socketxp.com/download](https://www.socketxp.com/download), dit stel in staat om tcp en http bloot te stel:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Van [https://ngrok.com/](https://ngrok.com/), dit stel jou in staat om http en tcp poorte bloot te stel:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Van [https://telebit.cloud/](https://telebit.cloud/) laat dit toe om http en tcp poorte bloot te stel:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Van [https://localxpose.io/](https://localxpose.io/) bied dit verskeie http en poort deurstuur funksies **gratis** aan.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Van [https://expose.dev/](https://expose.dev/) laat dit toe om http en tcp poorte bloot te stel:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Van [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) laat dit toe om http gratis bloot te stel:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
