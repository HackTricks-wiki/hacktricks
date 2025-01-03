{{#include ../../banners/hacktricks-training.md}}

फिशिंग आकलन के लिए कभी-कभी एक वेबसाइट को पूरी तरह से **क्लोन करना** उपयोगी हो सकता है।

ध्यान दें कि आप क्लोन की गई वेबसाइट में कुछ पेलोड भी जोड़ सकते हैं जैसे कि उपयोगकर्ता के टैब को "नियंत्रित" करने के लिए एक BeEF हुक।

इस उद्देश्य के लिए आप विभिन्न उपकरणों का उपयोग कर सकते हैं:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## सोशल इंजीनियरिंग टूलकिट
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
