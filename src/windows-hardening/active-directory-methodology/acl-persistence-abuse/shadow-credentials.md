# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**इस तकनीक के बारे में [सभी जानकारी के लिए मूल पोस्ट देखें](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)।**

**सारांश** के रूप में: यदि आप एक उपयोगकर्ता/कंप्यूटर की **msDS-KeyCredentialLink** प्रॉपर्टी में लिख सकते हैं, तो आप उस ऑब्जेक्ट का **NT हैश** प्राप्त कर सकते हैं।

पोस्ट में, एक विधि का वर्णन किया गया है जो **सार्वजनिक-निजी कुंजी प्रमाणीकरण क्रेडेंशियल्स** सेट करने के लिए है ताकि एक अद्वितीय **सेवा टिकट** प्राप्त किया जा सके जिसमें लक्षित का NTLM हैश शामिल हो। इस प्रक्रिया में Privilege Attribute Certificate (PAC) के भीतर एन्क्रिप्टेड NTLM_SUPPLEMENTAL_CREDENTIAL शामिल है, जिसे डिक्रिप्ट किया जा सकता है।

### Requirements

इस तकनीक को लागू करने के लिए, कुछ शर्तें पूरी होनी चाहिए:

- एक न्यूनतम Windows Server 2016 डोमेन कंट्रोलर की आवश्यकता है।
- डोमेन कंट्रोलर पर एक सर्वर प्रमाणीकरण डिजिटल सर्टिफिकेट स्थापित होना चाहिए।
- Active Directory को Windows Server 2016 फ़ंक्शनल लेवल पर होना चाहिए।
- लक्षित ऑब्जेक्ट की msDS-KeyCredentialLink विशेषता को संशोधित करने के लिए प्रतिनिधित्व अधिकारों के साथ एक खाता आवश्यक है।

## Abuse

कंप्यूटर ऑब्जेक्ट के लिए की ट्रस्ट का दुरुपयोग टिकट ग्रांटिंग टिकट (TGT) और NTLM हैश प्राप्त करने से परे कदमों को शामिल करता है। विकल्पों में शामिल हैं:

1. लक्षित होस्ट पर विशेषाधिकार प्राप्त उपयोगकर्ताओं के रूप में कार्य करने के लिए एक **RC4 सिल्वर टिकट** बनाना।
2. **विशेषाधिकार प्राप्त उपयोगकर्ताओं** के अनुकरण के लिए **S4U2Self** के साथ TGT का उपयोग करना, जिसके लिए सेवा नाम में सेवा वर्ग जोड़ने के लिए सेवा टिकट में परिवर्तन की आवश्यकता होती है।

की ट्रस्ट के दुरुपयोग का एक महत्वपूर्ण लाभ यह है कि यह हमलावर द्वारा उत्पन्न निजी कुंजी तक सीमित है, संभावित रूप से कमजोर खातों को प्रतिनिधित्व से बचाता है और एक कंप्यूटर खाता बनाने की आवश्यकता नहीं होती, जिसे हटाना चुनौतीपूर्ण हो सकता है।

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

यह इस हमले के लिए C# इंटरफेस प्रदान करने वाले DSInternals पर आधारित है। Whisker और इसके Python समकक्ष, **pyWhisker**, Active Directory खातों पर नियंत्रण प्राप्त करने के लिए `msDS-KeyCredentialLink` विशेषता में हेरफेर करने की अनुमति देते हैं। ये उपकरण लक्षित ऑब्जेक्ट से कुंजी क्रेडेंशियल्स को जोड़ने, सूचीबद्ध करने, हटाने और साफ़ करने जैसी विभिन्न कार्यवाहियों का समर्थन करते हैं।

**Whisker** कार्यक्षमताएँ शामिल हैं:

- **Add**: एक कुंजी जोड़ी उत्पन्न करता है और एक कुंजी क्रेडेंशियल जोड़ता है।
- **List**: सभी कुंजी क्रेडेंशियल प्रविष्टियों को प्रदर्शित करता है।
- **Remove**: निर्दिष्ट कुंजी क्रेडेंशियल को हटाता है।
- **Clear**: सभी कुंजी क्रेडेंशियल्स को मिटा देता है, संभावित रूप से वैध WHfB उपयोग को बाधित कर सकता है।
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

यह Whisker कार्यक्षमता को **UNIX-आधारित सिस्टम** पर बढ़ाता है, जिसमें KeyCredentials की सूची बनाने, जोड़ने और हटाने के लिए Impacket और PyDSInternals का उपयोग किया जाता है, साथ ही इन्हें JSON प्रारूप में आयात और निर्यात करने की व्यापक शोषण क्षमताएँ शामिल हैं।
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray का उद्देश्य **GenericWrite/GenericAll अनुमतियों का लाभ उठाना है जो व्यापक उपयोगकर्ता समूहों के पास डोमेन ऑब्जेक्ट्स पर हो सकते हैं** ताकि ShadowCredentials को व्यापक रूप से लागू किया जा सके। इसमें डोमेन में लॉग इन करना, डोमेन के कार्यात्मक स्तर की पुष्टि करना, डोमेन ऑब्जेक्ट्स की गणना करना, और TGT अधिग्रहण और NT हैश प्रकट करने के लिए KeyCredentials जोड़ने का प्रयास करना शामिल है। सफाई विकल्प और पुनरावृत्त शोषण रणनीतियाँ इसकी उपयोगिता को बढ़ाती हैं।

## References

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
