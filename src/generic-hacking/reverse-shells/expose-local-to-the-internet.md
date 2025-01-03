# Expose local to the internet

{{#include ../../banners/hacktricks-training.md}}

**इस पृष्ठ का लक्ष्य ऐसे विकल्पों का प्रस्ताव करना है जो कम से कम स्थानीय कच्चे TCP पोर्ट और स्थानीय वेब (HTTP) को इंटरनेट पर उजागर करने की अनुमति देते हैं बिना दूसरे सर्वर पर कुछ भी स्थापित किए (यदि आवश्यक हो तो केवल स्थानीय पर)।**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), it allows several http and port forwarding features **for free**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

From [https://www.socketxp.com/download](https://www.socketxp.com/download), यह tcp और http को एक्सपोज़ करने की अनुमति देता है:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) से, यह http और tcp पोर्ट्स को एक्सपोज़ करने की अनुमति देता है:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) से यह http और tcp पोर्ट्स को एक्सपोज़ करने की अनुमति देता है:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

From [https://localxpose.io/](https://localxpose.io/), यह कई http और पोर्ट फॉरवर्डिंग सुविधाएँ **मुफ्त** में प्रदान करता है।
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

From [https://expose.dev/](https://expose.dev/) यह http और tcp पोर्ट को एक्सपोज़ करने की अनुमति देता है:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

From [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) यह मुफ्त में http को एक्सपोज़ करने की अनुमति देता है:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
{{#include ../../banners/hacktricks-training.md}}
