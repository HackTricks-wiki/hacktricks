# 로컬을 인터넷에 노출하기

{{#include ../../banners/hacktricks-training.md}}

**이 페이지의 목표는 최소한 로컬 원시 TCP 포트와 로컬 웹(HTTP)을 인터넷에 노출할 수 있는 대안을 제안하는 것입니다. 다른 서버에 아무것도 설치할 필요 없이(필요한 경우 로컬에만 설치).**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), it allows several http and port forwarding features **for free**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download)에서 tcp와 http를 노출할 수 있습니다:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/)에서 http 및 tcp 포트를 노출할 수 있습니다:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/)에서 http 및 tcp 포트를 노출할 수 있습니다:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/)에서, 여러 http 및 포트 포워딩 기능을 **무료로** 제공합니다.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

From [https://expose.dev/](https://expose.dev/) http 및 tcp 포트를 노출할 수 있습니다:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)에서 무료로 http를 노출할 수 있습니다:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
