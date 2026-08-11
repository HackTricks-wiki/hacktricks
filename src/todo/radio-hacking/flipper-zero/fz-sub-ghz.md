# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#introduction" id="introduction"></a>

Flipper Zero अपने built-in module से **300-928 MHz की range में radio frequencies receive और transmit कर सकता है**, जो configured region के लिए frequency restrictions के अधीन है। यह gates, barriers, radio locks, switches, wireless doorbells, smart lights और अन्य devices में उपयोग किए जाने वाले compatible remote controls को पढ़, save और emulate कर सकता है।<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Hardware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero में CC1101 transceiver और radio antenna पर आधारित built-in sub-1 GHz module है। Actual range frequency, antenna, environment और transmitter पर निर्भर करती है; Flipper favorable conditions में लगभग 50 meters तक की range document करता है। Hardware 300-348 MHz, 387-464 MHz और 779-928 MHz को cover करता है, जबकि firmware और regional rules transmission को और restrict करते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!TIP]
> यह पता लगाने के लिए कि remote किस frequency का उपयोग कर रहा है

Analysis के दौरान Flipper Zero frequency configuration में उपलब्ध सभी frequencies पर signal strength (RSSI) scan करता है। Flipper Zero उस frequency को display करता है जिसका RSSI value सबसे अधिक होता है और signal strength -90 [dBm](https://en.wikipedia.org/wiki/DBm) से अधिक होती है।<sup>[[1]](#references)</sup>

Remote की frequency निर्धारित करने के लिए निम्नलिखित करें:

1. Remote control को Flipper Zero के बाईं ओर उसके बहुत पास रखें।
2. **Main Menu** **→ Sub-GHz** पर जाएं।
3. **Frequency Analyzer** select करें, फिर जिस remote control का analysis करना चाहते हैं उसका button दबाकर रखें।
4. Screen पर frequency value देखें।

### Read

> [!TIP]
> उपयोग की गई frequency की जानकारी प्राप्त करें (यह उपयोग की गई frequency पता करने का एक और तरीका है)

**Read** option configured frequency और modulation (default रूप से 433.92 MHz AM) पर listen करता है। जब यह किसी supported signal को पहचानता है, तो screen पर ऐसी information display होती है जिसे बाद में save और replay किया जा सकता है।<sup>[[1]](#references)</sup>

Read के उपयोग के दौरान **left button** दबाकर इसे **configure** करना संभव है।\
इस समय इसमें **4 modulations** (AM270, AM650, FM328 और FM476) और कई relevant frequencies stored हैं:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

आप कोई भी permitted frequency select कर सकते हैं। यदि आपको पता नहीं है कि remote किस frequency का उपयोग करता है, तो **Hopping को ON** करें (default रूप से off), फिर remote button को कई बार दबाएं, जब तक Flipper signal capture करके frequency report न कर दे।

> [!CAUTION]
> Frequencies के बीच switching में कुछ समय लगता है, इसलिए switching के समय transmit किए गए signals miss हो सकते हैं। बेहतर signal reception के लिए Frequency Analyzer द्वारा निर्धारित fixed frequency set करें।

### **Read Raw**

> [!TIP]
> Configured frequency पर signal को steal (और replay) करें

**Read Raw** option selected frequency पर भेजे गए signals को record करता है। इसका उपयोग authorized testing के दौरान किसी signal को capture और replay करने के लिए किया जा सकता है।<sup>[[1]](#references)</sup>

Default रूप से **Read Raw, AM650 के साथ 433.92 MHz का भी उपयोग करता है**। यदि Read option को किसी अलग frequency या modulation पर signal मिला है, तो उन settings को बदलने के लिए Read Raw के अंदर Left दबाएं।

### Brute-Force

यदि आपको garage door जैसे किसी device द्वारा उपयोग किए गए protocol का पता है, तो **candidate codes generate करके उन्हें Flipper Zero से transmit करना** संभव हो सकता है। `flipperzero-bruteforce` project कई common static-code protocols को support करता है।<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Configured protocols की list से signals add करें

#### List of supported protocols <a href="#id-3iglu" id="id-3iglu"></a>

Add Manually menu Flipper Zero द्वारा documented protocol presets उपलब्ध कराता है।<sup>[[4]](#references)</sup>

| Princeton_433 (अधिकांश static code systems के साथ काम करता है) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Supported Sub-GHz vendors

Flipper Zero की supported-vendors list देखें।<sup>[[5]](#references)</sup>

### Supported Frequencies by region

Transmit करने से पहले official regional-frequency list देखें।<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Saved frequencies के dBms प्राप्त करें

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
