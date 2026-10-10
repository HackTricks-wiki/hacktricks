# Crypto CTF विविध

{{#include ../../banners/hacktricks-training.md}}

इस अनुभाग में cryptography challenges में इस्तेमाल होने वाली ऐसी तकनीकें शामिल हैं, जो अन्य श्रेणियों में ठीक से नहीं आतीं।

## गूढ़ भाषाएँ

### तकनीक

जब किसी challenge में गूढ़-भाषा के प्रोग्राम को चलाकर उसका output decode करना हो, तब यह workflow अपनाएँ।

अगर challenge में ऐसा code दिया गया है जो किसी standard भाषा जैसा नहीं दिखता:

- किसी विशिष्ट token या निर्देशों के क्रम को खोजकर भाषा की पहचान करें।
- Online interpreter या Docker image का इस्तेमाल करें।
- अगर output अजीब हो, तो execution के बाद encoding या compression की परतें देखें।

उपयोगी भाषाओं की सूची Esolang wiki पर है।<sup>[[1]](#references)</sup>

## References

- [1] [Esolang, गूढ़ प्रोग्रामिंग भाषाओं की wiki](https://esolangs.org/wiki/Main_Page)
{{#include ../../banners/hacktricks-training.md}}
