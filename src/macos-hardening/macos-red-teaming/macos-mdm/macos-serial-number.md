# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

यह न मानें कि हर Mac में decode किया जा सकने वाला 12-character serial number होता है। Apple के पुराने format में manufacturing और configuration information encode की जाती थी, लेकिन Apple ने 2021 में नए products के साथ randomized serial numbers पेश करना शुरू किया। Randomized format में manufacturing या configuration details उजागर नहीं होतीं।<sup>[[1]](#references)</sup>

### Legacy 12-character format

2010 से randomized transition तक निर्मित कई devices के लिए, 12-character format अभी भी उपयोगी inventory clues दे सकता है:<sup>[[3]](#references)</sup>

- Characters 1–3 manufacturing location की पहचान करते हैं।
- Characters 4–5 production half-year और week को encode करते हैं।
- Characters 6–8 एक ही location और समय पर निर्मित units में अंतर करते हैं।
- Characters 9–12 model या configuration code की पहचान करते हैं।

उदाहरण के लिए, `C02L13ECF8J2` इस legacy structure का पालन करता है। Community-maintained factory mappings में United States locations के लिए `FC`, `F`, `XA`, `XB`, `QP`, और `G8` जैसे prefixes; Mexico के लिए `RN`; Cork के लिए `CK`; Czech Republic में Foxconn location के लिए `VM`; Singapore के लिए `SG` या `E`; Malaysia के लिए `MB`; Korea के लिए `PT` या `CY`; और Taiwan के लिए `EE`, `QT`, या `UV` शामिल हैं। `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3`, और `C7` सहित कई prefixes को Chinese facilities से संबद्ध किया गया है; `RM` को refurbished devices से संबद्ध किया गया है।<sup>[[3]](#references)</sup>

Fourth-character date codes `C` (2010 की पहली छमाही) से `Z` (2019 की दूसरी छमाही) तक चलते हैं, जिसके बाद sequence का दोबारा उपयोग किया जाता है। Fifth character के लिए, digits `1`–`9` weeks 1–9 को दर्शाते हैं, जबकि vowels और `S` को छोड़कर letters `C`–`Y` weeks 10–27 को दर्शाते हैं; जब fourth character किसी year की दूसरी छमाही को दर्शाता है, तो 26 जोड़ें।<sup>[[3]](#references)</sup>

ये mappings legacy triage के लिए उपयोगी हैं, लेकिन origin, age या authenticity का authoritative proof नहीं हैं। Result की पुष्टि Apple's inventory data के माध्यम से करें।

Reliable identification के लिए, device से serial number प्राप्त करें और character positions से model का अनुमान लगाने के बजाय Apple's coverage या technical-specification lookup का उपयोग करें।<sup>[[2]](#references)</sup>

### Serial number प्राप्त करें

Graphical interface इसे **Apple menu > About This Mac** के अंतर्गत प्रदर्शित करता है।<sup>[[2]](#references)</sup> Shell से, निम्नलिखित में से कोई भी command platform serial number पढ़ती है:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Serial number को authenticator नहीं, बल्कि identifier मानें: enrollment या ownership से जुड़े निर्णय लेने से पहले संबंधित Apple या MDM inventory workflow के माध्यम से device की पुष्टि करें।

## References

- [1] [MacRumors - Apple ने randomized serial numbers पर संक्रमण शुरू किया](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - अपने Mac का model name और serial number खोजें](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Apple serial number के पीछे का अर्थ समझें](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
