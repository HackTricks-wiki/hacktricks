# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero अपने built-in module की सहायता से **300-928 MHz की range में radio frequencies receive और transmit कर सकता है**, जो remote controls को read, save और emulate कर सकता है। इन controls का उपयोग gates, barriers, radio locks, remote control switches, wireless doorbells, smart lights और अन्य उपकरणों के साथ interaction के लिए किया जाता है। Flipper Zero आपको यह पता लगाने में मदद कर सकता है कि आपकी security compromised है या नहीं।

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero में [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) पर आधारित built-in sub-1 GHz module और एक radio antenna है (अधिकतम range 50 meters है)। CC1101 chip और antenna, दोनों को 300-348 MHz, 387-464 MHz और 779-928 MHz bands में operate करने के लिए design किया गया है।

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyzer

> [!TIP]
> यह पता लगाएं कि remote किस frequency का उपयोग कर रहा है

Analysis के दौरान Flipper Zero, frequency configuration में उपलब्ध सभी frequencies पर signal strength (RSSI) scan करता है। Flipper Zero सबसे अधिक RSSI value वाली frequency display करता है, जिसकी signal strength -90 [dBm](https://en.wikipedia.org/wiki/DBm) से अधिक होती है।<sup>[[1]](#references)</sup>

Remote की frequency निर्धारित करने के लिए निम्न कार्य करें:

1. Remote control को Flipper Zero के बाईं ओर, बहुत पास रखें।
2. **Main Menu** **→ Sub-GHz** पर जाएं।
3. **Frequency Analyzer** चुनें, फिर उस remote control का button दबाकर रखें जिसका analysis करना चाहते हैं।
4. Screen पर frequency value देखें।

### Read

> [!TIP]
> उपयोग की गई frequency की जानकारी प्राप्त करें (यह उपयोग की गई frequency पता करने का एक और तरीका भी है)

**Read** option, indicated modulation पर **configured frequency को listen करता है**: default रूप से 433.92 AM। यदि reading के दौरान **कुछ मिलता है**, तो screen पर **info दी जाती है**। इस info का उपयोग भविष्य में signal को replicate करने के लिए किया जा सकता है।<sup>[[1]](#references)</sup>

Read के उपयोग के दौरान **left button** दबाकर इसे **configure करना** संभव है।\
इस समय इसमें **4 modulations** (AM270, AM650, FM328 और FM476) और कई **relevant frequencies** stored हैं:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

आप अपनी रुचि की **कोई भी frequency set कर सकते हैं**, हालांकि, यदि आपको **यकीन नहीं है कि आपके remote द्वारा कौन-सी frequency** उपयोग की जाती है, तो **Hopping को ON** (default रूप से Off) करें और button को कई बार दबाएं, जब तक Flipper उसे capture करके आपको frequency set करने के लिए आवश्यक info न दे दे।

> [!CAUTION]
> Frequencies के बीच switch करने में कुछ समय लगता है, इसलिए switching के समय transmit किए गए signals miss हो सकते हैं। बेहतर signal reception के लिए Frequency Analyzer द्वारा निर्धारित fixed frequency set करें।

### **Read Raw**

> [!TIP]
> Configured frequency पर signal को steal करें (और replay करें)

**Read Raw** option listening frequency पर भेजे गए **signals को record करता है**। इसका उपयोग किसी signal को **steal** करके उसे **repeat** करने के लिए किया जा सकता है।<sup>[[1]](#references)</sup>

Default रूप से **Read Raw भी AM650 में 433.92 पर होता है**, लेकिन यदि Read option से आपको पता चला कि आपकी रुचि का signal **किसी अलग frequency/modulation पर है, तो left दबाकर इसे भी modify कर सकते हैं** (Read Raw option के अंदर रहते हुए)।

### Brute-Force

यदि आपको garage door द्वारा उपयोग किए जाने वाले protocol की जानकारी है, तो **सभी codes generate करके उन्हें Flipper Zero से send करना संभव है।** यह एक example है जो सामान्य garage के common types को support करता है: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Configured protocols की list से signals add करें

#### [supported protocols](https://docs.flipperzero.one/sub-ghz/add-new-remote) की list <a href="#id-3iglu" id="id-3iglu"></a>

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

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) पर list देखें

### Supported Frequencies by region

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) पर list देखें

### Test

> [!TIP]
> Saved frequencies के dBms प्राप्त करें

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
