# Вивести локаль в інтернет

{{#include ../../banners/hacktricks-training.md}}

**Мета цієї сторінки - запропонувати альтернативи, які дозволяють ПРИНАЙМНІ вивести локальні сирі TCP порти та локальні веб-сайти (HTTP) в інтернет БЕЗ необхідності встановлювати щось на іншому сервері (тільки локально, якщо це потрібно).**

## **Serveo**

З [https://serveo.net/](https://serveo.net/), він дозволяє кілька функцій перенаправлення http та портів **безкоштовно**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

З [https://www.socketxp.com/download](https://www.socketxp.com/download) він дозволяє відкрити tcp та http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

З [https://ngrok.com/](https://ngrok.com/), він дозволяє відкривати http та tcp порти:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

З [https://telebit.cloud/](https://telebit.cloud/) він дозволяє відкривати http та tcp порти:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

З [https://localxpose.io/](https://localxpose.io/) це дозволяє кілька функцій http та переадресації портів **безкоштовно**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

З [https://expose.dev/](https://expose.dev/) можна відкрити http та tcp порти:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

З [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) це дозволяє безкоштовно відкривати http:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
