# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Infrared कैसे काम करता है, इसके बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero में IR Signal Receiver <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper एक डिजिटल IR signal receiver TSOP का उपयोग करता है, जो **IR remotes से signals को intercept करने की अनुमति देता है**। Xiaomi जैसे कुछ **smartphones** में भी IR port होता है, लेकिन ध्यान रखें कि **इनमें से अधिकांश केवल signals transmit कर सकते हैं** और **उन्हें receive करने में सक्षम नहीं होते**।<sup>[[1]](#references)</sup>

Flipper का infrared **receiver काफी sensitive है**। आप remote और TV के बीच **कहीं बीच में रहते हुए भी signal को catch कर सकते हैं**। Remote को सीधे Flipper के IR port की ओर point करना आवश्यक नहीं है। यह तब उपयोगी होता है जब कोई व्यक्ति TV के पास खड़े होकर channels बदल रहा हो और आप तथा Flipper दोनों कुछ दूरी पर हों।

क्योंकि infrared signal का **decoding software side** पर होता है, Flipper Zero संभावित रूप से **किसी भी IR remote codes को receive और transmit कर सकता है**। ऐसे **unknown** protocols के मामले में जिन्हें पहचाना नहीं जा सका, यह raw signal को ठीक वैसे ही **record और playback करता है**, जैसे वह receive हुआ था।<sup>[[1]](#references)</sup>

## Actions

### Universal Remotes

Flipper Zero का उपयोग **किसी भी TV, air conditioner या media center को control करने के लिए universal remote के रूप में** किया जा सकता है। इस mode में Flipper, **SD card की dictionary के अनुसार**, समर्थित सभी manufacturers के सभी **known codes को bruteforce** करता है। Restaurant के TV को बंद करने के लिए आपको किसी particular remote को चुनने की आवश्यकता नहीं है।<sup>[[1]](#references)</sup>

Universal Remote mode में power button दबाना पर्याप्त है और Flipper अपने knowledge में मौजूद सभी TVs के **"Power Off"** commands को **sequentially send** करेगा: Sony, Samsung, Panasonic... और इसी तरह। जब TV उसका signal receive करेगा, तो वह प्रतिक्रिया करके बंद हो जाएगा।

ऐसे brute-force में समय लगता है। Dictionary जितनी बड़ी होगी, इसे पूरा होने में उतना ही अधिक समय लगेगा। यह पता लगाना संभव नहीं है कि TV ने ठीक किस signal को recognize किया, क्योंकि TV की ओर से कोई feedback नहीं मिलता।

### नया Remote सीखना

Flipper Zero से **infrared signal capture करना** संभव है। यदि उसे database में **signal मिल जाता है**, तो Flipper अपने-आप **जान जाएगा कि यह कौन-सा device है** और आपको उसके साथ interact करने देगा।\
यदि signal नहीं मिलता, तो Flipper **signal को store** कर सकता है और आपको उसे **replay करने की अनुमति देगा**।<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero Infrared Port से TVs को Take Over करना](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
