# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

इस पृष्ठ का लक्ष्य **प्लेटफार्मों की गणना करना है जो कोड** (शाब्दिक या regex) को हजारों/लाखों रिपोजिटरी में एक या एक से अधिक प्लेटफार्मों में खोजने की अनुमति देते हैं।

यह कई अवसरों पर **लीक की गई जानकारी** या **कमजोरियों** के पैटर्न खोजने में मदद करता है।

- [**SourceGraph**](https://sourcegraph.com/search): लाखों रिपोजिटरी में खोजें। इसमें एक मुफ्त संस्करण और एक एंटरप्राइज संस्करण है (15 दिन मुफ्त)। यह regex का समर्थन करता है।
- [**Github Search**](https://github.com/search): Github में खोजें। यह regex का समर्थन करता है।
- शायद [**Github Code Search**](https://cs.github.com/) की जांच करना भी उपयोगी हो।
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Gitlab परियोजनाओं में खोजें। regex का समर्थन करता है।
- [**SearchCode**](https://searchcode.com/): लाखों परियोजनाओं में कोड खोजें।

> [!WARNING]
> जब आप किसी रिपोजिटरी में लीक की तलाश कर रहे हों और कुछ ऐसा चलाते हैं जैसे `git log -p` तो न भूलें कि वहाँ **अन्य शाखाएँ हो सकती हैं जिनमें अन्य कमिट्स** हो सकते हैं जिनमें रहस्य हो सकते हैं!

{{#include ../../banners/hacktricks-training.md}}
