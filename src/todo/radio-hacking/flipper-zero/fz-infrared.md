# FZ - इन्फ्रारेड

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Infrared कैसे काम करता है, इसके बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero में IR Signal Receiver <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero सामान्य IR remotes से signals capture करने के लिए एक demodulating IR receiver का उपयोग करता है। कुछ phones, जिनमें कुछ Xiaomi models भी शामिल हैं, में IR transmitter होता है, लेकिन अधिकांश remote-control signals को receive और decode नहीं कर सकते।<sup>[[1]](#references)</sup>

Flipper का infrared **receiver काफी sensitive है**। आप remote और TV के **बीच कहीं रहते हुए भी signal पकड़ सकते हैं**। Remote को सीधे Flipper के IR port की ओर point करना आवश्यक नहीं है। यह तब उपयोगी होता है जब कोई व्यक्ति TV के पास खड़े होकर channels बदल रहा हो और आप तथा Flipper दोनों कुछ दूरी पर हों।

Protocol decoding software में होता है। Recognized protocols को decoded commands के रूप में store किया जा सकता है; unsupported protocols को raw timing data के रूप में capture और replay किया जा सकता है, जो hardware की carrier-frequency और timing limits के अधीन होता है।<sup>[[1]](#references)</sup>

## Actions

### Universal Remotes

Flipper Zero का universal-remote mode supported TVs, audio equipment, projectors और air conditioners के लिए अपने infrared database में मौजूद known commands को बारी-बारी से भेजता है। हर device को control करने की guarantee नहीं है, और इसका उपयोग केवल अपने या test करने की authorization वाले equipment पर किया जाना चाहिए।<sup>[[1]](#references)</sup>

Universal Remote mode में power button दबाना पर्याप्त है, और Flipper उन सभी TVs के **"Power Off"** commands को **क्रमिक रूप से भेजेगा** जिन्हें वह जानता है: Sony, Samsung, Panasonic... और इसी तरह। जब TV इसका signal receive करता है, तो वह प्रतिक्रिया करके बंद हो जाएगा।

ऐसे brute-force में समय लगता है। Dictionary जितना बड़ा होगा, इसे पूरा होने में उतना ही अधिक समय लगेगा। यह पता लगाना संभव नहीं है कि TV ने ठीक किस signal को recognize किया, क्योंकि TV की ओर से कोई feedback नहीं मिलता।

### Learn New Remote

Flipper Zero **infrared signal capture** कर सकता है। यदि यह protocol और command को recognize करता है, तो decoded representation store करता है; अन्यथा, यह raw timing data को बाद में replay करने के लिए store कर सकता है।<sup>[[1]](#references)</sup>

## References

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
