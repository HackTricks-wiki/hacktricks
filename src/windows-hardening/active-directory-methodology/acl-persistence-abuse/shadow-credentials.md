# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#3f17" id="3f17"></a>

**इस technique के बारे में [सभी जानकारी के लिए original post देखें](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)।**<sup>[[1]](#references)</sup>

संक्षेप में, किसी user या computer के **`msDS-KeyCredentialLink`** पर control होने से attacker एक key credential जोड़ सकता है, PKINIT के साथ उस object के रूप में authenticate कर सकता है, और—जब KDC तथा account आवश्यक flows को support करते हों—resulting ticket को `S4U2Self`/user-to-user के साथ उपयोग करके object का NT hash प्राप्त कर सकता है।<sup>[[1]](#references)</sup>

इस post में **public-private key authentication credentials** सेट करने की एक method बताई गई है, जिससे target का NTLM hash शामिल करने वाला एक unique **Service Ticket** प्राप्त किया जा सके। इस process में Privilege Attribute Certificate (PAC) के भीतर encrypted NTLM_SUPPLEMENTAL_CREDENTIAL शामिल होता है, जिसे decrypt किया जा सकता है।<sup>[[1]](#references)</sup>

### आवश्यकताएँ

इस technique को लागू करने के लिए कुछ conditions पूरी होनी चाहिए:<sup>[[1]](#references)</sup>

- कम-से-कम एक Windows Server 2016 Domain Controller आवश्यक है।
- Domain Controller पर server authentication digital certificate installed होना चाहिए।
- Directory schema में `msDS-KeyCredentialLink` होना चाहिए; research में वर्णित practical platform requirements के अनुसार Windows Server 2016 या newer DC और KDC पर PKINIT-capable certificate आवश्यक हैं। Exploitability का निर्णय केवल domain functional-level label के आधार पर लेने के बजाय domain के schema/DC mix को verify करें।
- Target object के `msDS-KeyCredentialLink` attribute को modify करने के लिए delegated rights वाला account आवश्यक है।

## Abuse

Computer objects के लिए Key Trust का abuse करने में Ticket Granting Ticket (TGT) और NTLM hash प्राप्त करने से आगे के steps शामिल होते हैं। Options में शामिल हैं:<sup>[[1]](#references)</sup>

1. Intended host पर privileged users के रूप में act करने के लिए एक **RC4 silver ticket** बनाना।
2. **privileged users** का impersonation करने के लिए TGT को **S4U2Self** के साथ उपयोग करना; इसके लिए Service Ticket में बदलाव करके service name में service class जोड़ना आवश्यक है।

Key Trust abuse का एक महत्वपूर्ण लाभ यह है कि यह attacker-generated private key तक सीमित रहता है, जिससे potentially vulnerable accounts को delegation देने से बचा जा सकता है। इसके अलावा, computer account बनाने की आवश्यकता नहीं होती, जिसे हटाना challenging हो सकता है।<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker, C# से `msDS-KeyCredentialLink` को manipulate करने के लिए DSInternals का उपयोग करता है। Whisker और इसका Python counterpart **pyWhisker** key credentials को add, list, remove और clear करने का support करते हैं।<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** के functions में शामिल हैं:

- **Add**: एक key pair generate करता है और key credential add करता है।
- **List**: सभी key credential entries display करता है।
- **Remove**: निर्दिष्ट key credential delete करता है।
- **Clear**: सभी key credentials erase करता है, जिससे legitimate WHfB usage बाधित हो सकता है।
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker, Impacket और PyDSInternals के साथ **UNIX-like systems** में workflow लाता है, जिसमें list/add/remove और JSON import/export operations शामिल हैं।<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray उन domain objects को enumerate करता है जिन पर operator के पास `GenericWrite`/`GenericAll` जैसे rights होते हैं, व्यापक रूप से key credentials जोड़ने का प्रयास करता है, और cleanup/recursive modes शामिल करता है। व्यापक spraying disruptive और conspicuous होता है; explicit targets का उपयोग करें और सटीक removal के लिए जोड़े गए प्रत्येक DeviceID को सुरक्षित रखें।<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Account Takeover के लिए Key Trust Account Mapping का दुरुपयोग](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink में बदलाव करके AD accounts पर takeover करने का Tool](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - पूरे domain में Shadow Credentials spray करने का Tool](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials tool का Python version](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
