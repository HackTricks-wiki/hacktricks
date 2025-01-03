# 将本地暴露到互联网

{{#include ../../banners/hacktricks-training.md}}

**本页面的目标是提出替代方案，至少允许将本地原始 TCP 端口和本地网页 (HTTP) 暴露到互联网，而无需在其他服务器上安装任何东西（仅在本地需要时）。**

## **Serveo**

来自 [https://serveo.net/](https://serveo.net/)，它允许多种 HTTP 和端口转发功能 **免费**。
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

从 [https://www.socketxp.com/download](https://www.socketxp.com/download) ，它允许暴露 tcp 和 http：
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

来自 [https://ngrok.com/](https://ngrok.com/)，它允许暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

从 [https://telebit.cloud/](https://telebit.cloud/) 它允许暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

来自 [https://localxpose.io/](https://localxpose.io/)，它提供多个 http 和端口转发功能 **免费**。
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

从 [https://expose.dev/](https://expose.dev/) 它允许暴露 http 和 tcp 端口：
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

来自 [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)，它允许免费暴露 http：
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
