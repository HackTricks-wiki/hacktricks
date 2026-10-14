# FZ - इन्फ्रारेड

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

इन्फ्रारेड कैसे काम करता है, इसकी अधिक जानकारी के लिए देखें:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero में IR सिग्नल रिसीवर <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero आम IR रिमोट से सिग्नल कैप्चर करने के लिए demodulating IR receiver का उपयोग करता है। कुछ फ़ोन, जिनमें Xiaomi के कुछ मॉडल शामिल हैं, में IR transmitter होता है, लेकिन ज़्यादातर फ़ोन रिमोट-कंट्रोल सिग्नल प्राप्त और decode नहीं कर सकते।<sup>[[1]](#references)</sup>

Flipper का infrared **receiver काफ़ी संवेदनशील है**। आप रिमोट और TV के **बीच कहीं खड़े रहकर भी सिग्नल पकड़ सकते हैं**। रिमोट को सीधे Flipper के IR पोर्ट की ओर करना ज़रूरी नहीं है। यह तब काम आता है जब कोई TV के पास खड़े होकर चैनल बदल रहा हो, और आप तथा Flipper दोनों उससे कुछ दूरी पर हों।

Protocol decoding सॉफ़्टवेयर में होती है। पहचाने गए protocols को decoded commands के रूप में सहेजा जा सकता है; unsupported protocols को raw timing data के रूप में कैप्चर करके फिर से चलाया जा सकता है, जो हार्डवेयर की carrier-frequency और timing सीमाओं के अधीन है।<sup>[[1]](#references)</sup>

## कार्रवाइयाँ

### Universal Remotes

Flipper Zero का universal-remote mode, समर्थित TVs, audio equipment, projectors और air conditioners के लिए अपने infrared database में मौजूद ज्ञात commands को बारी-बारी से भेजता है। यह हर device को नियंत्रित कर पाएगा, इसकी गारंटी नहीं है। इसका उपयोग केवल उन उपकरणों पर करें जिनके आप मालिक हैं या जिन्हें test करने की आपको अनुमति है।<sup>[[1]](#references)</sup>

Universal Remote mode में power button दबाना काफ़ी है। Flipper उन सभी TVs को क्रम से **"Power Off" commands भेजेगा** जिन्हें वह जानता है: Sony, Samsung, Panasonic... और इसी तरह अन्य। जब TV को इसका सिग्नल मिलता है, तो वह प्रतिक्रिया करके बंद हो जाएगा।

इस तरह brute-force करने में समय लगता है। Dictionary जितनी बड़ी होगी, इसे पूरा होने में उतना ही अधिक समय लगेगा। यह पता लगाना असंभव है कि TV ने ठीक किस सिग्नल को पहचाना, क्योंकि TV से कोई feedback नहीं मिलता।

### नया रिमोट सीखें

Flipper Zero **इन्फ्रारेड सिग्नल कैप्चर कर सकता है**। अगर वह protocol और command पहचान लेता है, तो decoded representation सहेजता है; अन्यथा, वह बाद में फिर से चलाने के लिए raw timing data सहेज सकता है।<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero Infrared Port से TVs पर नियंत्रण पाना](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
