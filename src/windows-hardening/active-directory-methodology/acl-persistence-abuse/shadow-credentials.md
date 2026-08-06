# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## परिचय <a href="#3f17" id="3f17"></a>

**इस technique के बारे में [सभी जानकारी के लिए original post देखें](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)।**<sup>[[1]](#references)</sup>

**सारांश** के रूप में: यदि आप किसी user/computer की **msDS-KeyCredentialLink** property में लिख सकते हैं, तो आप **उस object का NT hash** प्राप्त कर सकते हैं।<sup>[[1]](#references)</sup>

इस post में **public-private key authentication credentials** स्थापित करने की एक method बताई गई है, जिससे एक unique **Service Ticket** प्राप्त किया जा सकता है जिसमें target का NTLM hash शामिल होता है। इस process में Privilege Attribute Certificate (PAC) के भीतर मौजूद encrypted NTLM_SUPPLEMENTAL_CREDENTIAL शामिल होता है, जिसे decrypt किया जा सकता है।<sup>[[1]](#references)</sup>

### आवश्यकताएँ

इस technique को लागू करने के लिए कुछ conditions पूरी होनी चाहिए:<sup>[[1]](#references)</sup>

- कम से कम एक Windows Server 2016 Domain Controller आवश्यक है।
- Domain Controller पर server authentication digital certificate installed होना चाहिए।
- Active Directory का Windows Server 2016 Functional Level पर होना आवश्यक है।
- target object के msDS-KeyCredentialLink attribute को modify करने के लिए delegated rights वाला account आवश्यक है।

## दुरुपयोग

Computer objects के लिए Key Trust के abuse में Ticket Granting Ticket (TGT) और NTLM hash प्राप्त करने के अलावा भी कुछ steps शामिल होते हैं। Options में शामिल हैं:<sup>[[1]](#references)</sup>

1. Intended host पर privileged users के रूप में कार्य करने के लिए **RC4 silver ticket** बनाना।
2. **privileged users** का impersonation करने के लिए TGT को **S4U2Self** के साथ उपयोग करना; इसके लिए service name में service class जोड़ने हेतु Service Ticket में modifications आवश्यक होते हैं।

Key Trust abuse का एक महत्वपूर्ण advantage यह है कि यह केवल attacker-generated private key तक सीमित रहता है। इससे potentially vulnerable accounts को delegation देने की आवश्यकता नहीं होती और computer account बनाने की भी जरूरत नहीं पड़ती, जिसे बाद में remove करना challenging हो सकता है।<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

यह DSInternals पर आधारित है और इस attack के लिए C# interface प्रदान करता है। Whisker और इसका Python counterpart, **pyWhisker**, Active Directory accounts पर control प्राप्त करने के लिए `msDS-KeyCredentialLink` attribute में manipulation की सुविधा देते हैं। ये tools target object से key credentials को add, list, remove और clear करने जैसी विभिन्न operations support करते हैं।

**Whisker** के functions में शामिल हैं:

- **Add**: एक key pair generate करता है और key credential add करता है।
- **List**: सभी key credential entries display करता है।
- **Remove**: specified key credential delete करता है।
- **Clear**: सभी key credentials erase करता है, जिससे legitimate WHfB usage potentially disrupt हो सकता है।
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

यह Whisker की functionality को **UNIX-based systems** तक विस्तारित करता है और व्यापक exploitation capabilities के लिए Impacket तथा PyDSInternals का उपयोग करता है, जिसमें KeyCredentials को list करना, add करना और remove करना, साथ ही उन्हें JSON format में import और export करना शामिल है।
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray का उद्देश्य **wide user groups के domain objects पर मौजूद GenericWrite/GenericAll permissions को exploit करके** बड़े स्तर पर ShadowCredentials लागू करना है। इसमें domain में login करना, domain के functional level को verify करना, domain objects को enumerate करना और TGT acquisition तथा NT hash revelation के लिए KeyCredentials जोड़ने का प्रयास करना शामिल है। Cleanup options और recursive exploitation tactics इसकी उपयोगिता को बढ़ाते हैं।

## References

- [1] [Shadow Credentials: Account Takeover के लिए Key Trust Account Mapping का Abusing](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink में बदलाव करके AD accounts पर कब्ज़ा करने का Tool](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - पूरे domain में Shadow Credentials spray करने का Tool](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials tool का Python version](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
