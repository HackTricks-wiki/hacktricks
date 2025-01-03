# インターネットにローカルを公開する

{{#include ../../banners/hacktricks-training.md}}

**このページの目的は、他のサーバーに何もインストールすることなく（必要に応じてローカルにのみ）、ローカルの生TCPポートとローカルウェブ（HTTP）をインターネットに公開するための代替手段を提案することです。**

## **Serveo**

From [https://serveo.net/](https://serveo.net/)、いくつかのHTTPおよびポート転送機能を**無料で**提供しています。
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download) から、tcp と http を公開することができます。
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) から、http および tcp ポートを公開することができます：
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) から、http および tcp ポートを公開することができます:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/) から、いくつかの http およびポートフォワーディング機能を **無料** で提供しています。
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

From [https://expose.dev/](https://expose.dev/) は、httpおよびtcpポートを公開することを可能にします:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) から、無料でhttpを公開することができます:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
