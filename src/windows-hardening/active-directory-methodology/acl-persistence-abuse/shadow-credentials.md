# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#3f17" id="3f17"></a>

**इस तकनीक के बारे में [सारी जानकारी](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के लिए मूल पोस्ट देखें।**<sup>[[1]](#references)</sup>

संक्षेप में, किसी उपयोगकर्ता या कंप्यूटर के **`msDS-KeyCredentialLink`** पर नियंत्रण होने से हमलावर key credential जोड़ सकता है, PKINIT के ज़रिए उस ऑब्जेक्ट के रूप में authenticate कर सकता है और—जब KDC और अकाउंट ज़रूरी flows को support करते हों—मिली हुई ticket के साथ `S4U2Self`/user-to-user का उपयोग करके ऑब्जेक्ट का NT hash प्राप्त कर सकता है।<sup>[[1]](#references)</sup>

पोस्ट में **public-private key authentication credentials** सेट करने की एक विधि बताई गई है, जिससे एक विशिष्ट **Service Ticket** प्राप्त होती है जिसमें target का NTLM hash शामिल होता है। इस प्रक्रिया में Privilege Attribute Certificate (PAC) के भीतर मौजूद encrypted NTLM_SUPPLEMENTAL_CREDENTIAL शामिल है, जिसे decrypt किया जा सकता है।<sup>[[1]](#references)</sup>

### आवश्यकताएँ

इस तकनीक का उपयोग करने के लिए कुछ शर्तें पूरी होनी चाहिए:<sup>[[1]](#references)</sup>

- कम-से-कम एक Windows Server 2016 Domain Controller आवश्यक है।
- Domain Controller पर server authentication digital certificate इंस्टॉल होना चाहिए।
- Directory schema में `msDS-KeyCredentialLink` होना चाहिए; शोध में बताई गई व्यावहारिक platform आवश्यकताएँ Windows Server 2016 या नए DC और KDC पर PKINIT-capable certificate हैं। Exploitability तय करने के लिए केवल domain functional-level label पर निर्भर न रहें; domain के schema/DC mix की जाँच करें।
- Target object के msDS-KeyCredentialLink attribute को modify करने के लिए delegated rights वाला अकाउंट आवश्यक है।

## दुरुपयोग

Computer objects के लिए Key Trust के दुरुपयोग में Ticket Granting Ticket (TGT) और NTLM hash प्राप्त करने से आगे के चरण शामिल हैं। विकल्पों में शामिल हैं:<sup>[[1]](#references)</sup>

1. इच्छित host पर privileged users के रूप में काम करने के लिए **RC4 silver ticket** बनाना।
2. **privileged users** का impersonation करने के लिए TGT के साथ **S4U2Self** का उपयोग करना। इसके लिए Service Ticket में बदलाव करके service name में service class जोड़ना आवश्यक है।

Key Trust के दुरुपयोग का एक बड़ा लाभ यह है कि यह हमलावर द्वारा बनाई गई private key तक सीमित रहता है। इससे संभावित रूप से vulnerable accounts को delegation देने की ज़रूरत नहीं पड़ती और computer account बनाने की भी आवश्यकता नहीं होती, जिसे हटाना मुश्किल हो सकता है।<sup>[[1]](#references)</sup>

## टूल्स

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker, C# से `msDS-KeyCredentialLink` को manipulate करने के लिए DSInternals का उपयोग करता है। Whisker और इसका Python counterpart **pyWhisker**, key credentials जोड़ने, सूचीबद्ध करने, हटाने और साफ़ करने की सुविधा देते हैं।<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** के functions में शामिल हैं:

- **Add**: Key pair बनाता है और key credential जोड़ता है।
- **List**: सभी key credential entries दिखाता है।
- **Remove**: निर्दिष्ट key credential हटाता है।
- **Clear**: सभी key credentials मिटाता है, जिससे वैध WHfB उपयोग बाधित हो सकता है।

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker, Impacket और PyDSInternals के साथ **UNIX-जैसे सिस्टम** पर workflow लाता है, जिसमें सूची बनाने/जोड़ने/हटाने और JSON import/export operations शामिल हैं।<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray उन domain objects को enumerate करता है जिन पर operator के पास `GenericWrite`/`GenericAll` जैसे rights होते हैं, बड़े पैमाने पर key credentials जोड़ने का प्रयास करता है, और इसमें cleanup/recursive modes शामिल हैं। बड़े पैमाने पर spraying से व्यवधान हो सकता है और यह आसानी से ध्यान आकर्षित करता है; स्पष्ट targets का उपयोग करें और सटीक रूप से हटाने के लिए जोड़े गए हर DeviceID को दर्ज रखें।<sup>[[3]](#references)</sup>

जब direct LDAP फ़िल्टर किया गया हो, तब ADWS के ज़रिए key-credential write किया जा सकता है। [SOAPy ADWS workflow](../adws-enumeration.md#shadow-credentials-over-adws) देखें।<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Account Takeover के लिए Key Trust Account Mapping का दुरुपयोग](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink में बदलाव करके AD accounts पर कब्ज़ा करने का tool](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - पूरे domain में Shadow Credentials spray करने का tool](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials tool का Python version](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
