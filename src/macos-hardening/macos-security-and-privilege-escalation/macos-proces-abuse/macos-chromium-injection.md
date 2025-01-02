# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Chromium-आधारित ब्राउज़र जैसे Google Chrome, Microsoft Edge, Brave, और अन्य। ये ब्राउज़र Chromium ओपन-सोर्स प्रोजेक्ट पर आधारित हैं, जिसका मतलब है कि वे एक सामान्य आधार साझा करते हैं और इसलिए, उनके पास समान कार्यक्षमताएँ और डेवलपर विकल्प होते हैं।

#### `--load-extension` Flag

`--load-extension` फ्लैग का उपयोग कमांड लाइन या स्क्रिप्ट से Chromium-आधारित ब्राउज़र शुरू करते समय किया जाता है। यह फ्लैग **ब्राउज़र के प्रारंभ होने पर एक या अधिक एक्सटेंशन को स्वचालित रूप से लोड करने** की अनुमति देता है।

#### `--use-fake-ui-for-media-stream` Flag

`--use-fake-ui-for-media-stream` फ्लैग एक और कमांड-लाइन विकल्प है जिसका उपयोग Chromium-आधारित ब्राउज़र शुरू करने के लिए किया जा सकता है। यह फ्लैग **कैमरा और माइक्रोफोन से मीडिया स्ट्रीम तक पहुँचने के लिए अनुमति मांगने वाले सामान्य उपयोगकर्ता संकेतों को बायपास करने** के लिए डिज़ाइन किया गया है। जब इस फ्लैग का उपयोग किया जाता है, तो ब्राउज़र किसी भी वेबसाइट या एप्लिकेशन को स्वचालित रूप से अनुमति देता है जो कैमरा या माइक्रोफोन तक पहुँचने का अनुरोध करता है।

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Example
```bash
# Intercept traffic
voodoo intercept -b chrome
```
उदाहरणों को उपकरणों के लिंक में खोजें

## संदर्भ

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
