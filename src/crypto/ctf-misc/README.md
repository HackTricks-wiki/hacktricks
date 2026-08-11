# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

यह section उन techniques को एकत्र करता है जो cryptography challenges में दिखाई देती हैं, लेकिन अन्य categories में आसानी से fit नहीं होतीं।

## Esoteric languages

### Technique

जब किसी challenge में esoteric-language program चलाना और उसके output को decode करना आवश्यक हो, तब इस workflow का उपयोग करें।

यदि किसी challenge में ऐसा code दिया गया है जो किसी standard language जैसा नहीं दिखता:

- किसी विशिष्ट token या instruction sequence को search करके language की पहचान करें।
- किसी online interpreter या Docker image का उपयोग करें।
- यदि output अजीब है, तो execution के बाद layered encoding/compression खोजें।

एक उपयोगी language index Esolang wiki है।<sup>[[1]](#references)</sup>

## References

- [1] [Esolang, esoteric programming languages की wiki](https://esolangs.org/wiki/Main_Page)
{{#include ../../banners/hacktricks-training.md}}
