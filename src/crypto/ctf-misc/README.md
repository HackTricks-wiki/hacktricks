# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

यह section उन techniques को एकत्र करता है जो cryptography challenges में दिखाई देती हैं, लेकिन अन्य categories में ठीक से fit नहीं होतीं।

## Esoteric languages

### Technique

जब किसी challenge में esoteric-language program चलाकर उसका output decode करना हो, तो इस workflow का उपयोग करें।

अगर challenge में ऐसा code दिया गया है जो किसी standard language जैसा नहीं दिखता:

- किसी विशिष्ट token या instruction sequence को खोजकर language पहचानें।
- Online interpreter या Docker image का उपयोग करें।
- अगर output अजीब है, तो execution के बाद layered encoding/compression देखें।

Esolang wiki में languages की एक उपयोगी सूची है।<sup>[[1]](#references)</sup> सामान्य encoding और compression layers के लिए [Crypto CTF workflow](../ctf-workflow/) का उपयोग करें। अगर clue executable syntax के बजाय invisible text है, तो [text steganography](../../stego/text/) देखें।

### Preloaded interpreter state को exfiltrate करना

अगर कोई challenge esoteric-language source स्वीकार करता है और उसे **custom interpreter** में चलाता है, तो source को decoding puzzle मानने से पहले उसकी initial memory, stack और output instructions देखें। जब interpreter किसी secret को Befunge stack पर preload करता है, तो एक छोटा program गणना किए बिना मौजूदा bytes को pop करके print कर सकता है। इसके लिए executed source और output opcode पर control चाहिए; यह सामान्य empty interpreter के विरुद्ध काम नहीं करता। एक Befunge challenge में, नीचे दिया गया input stack पर reverse order में preload किए गए flag के characters को बार-बार output करता था।<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` दाईं ओर execution शुरू करता है, `,` एक character को pop करके प्रिंट करता है, और `<` instruction pointer को वापस `,` पर भेजता है। Custom interpreter के underflow और instruction-limit behavior की जाँच करें: उद्धृत implementation stack खाली होने पर या 1,024 instructions के बाद रुक जाता है। अगर secret सीधे stack पर मौजूद न हो, तो standard Befunge semantics मानने के बजाय दूसरी initialized state और उपलब्ध output/read instructions की जाँच करें।<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, गूढ़ प्रोग्रामिंग भाषाओं का विकि](https://esolangs.org/wiki/Main_Page)
- [2] [WolvCTF 2024 Befuddled1 का मूल writeup](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [WolvCTF 2024 Befuddled1 interpreter का स्रोत](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Befunge भाषा संदर्भ](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
