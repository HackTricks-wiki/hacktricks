# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

यह application entitlement **`com.apple.security.temporary-exception.sbpl`** का उपयोग करके एक **custom Sandbox** इस्तेमाल करता है। यह custom sandbox कहीं भी files लिखने की अनुमति देता है, बशर्ते filename `~$` से शुरू हो: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

इसलिए escape करना केवल **`plist`** LaunchAgent को `~/Library/LaunchAgents/~$escape.plist` में लिखने जितना आसान था।

[**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) देखें।<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

याद रखें कि पहले escape से Word ऐसी arbitrary files लिख सकता है जिनके नाम `~$` से शुरू होते हैं, हालांकि पिछली vuln के patch के बाद `/Library/Application Scripts` या `/Library/LaunchAgents` में लिखना संभव नहीं था।

यह पता चला कि sandbox के भीतर से **Login Item** बनाना संभव है (ऐसे apps जो user के login करने पर execute होते हैं)। हालांकि, ये apps **तब तक execute नहीं होंगे जब तक** वे **notarized** न हों और **args जोड़ना संभव नहीं है** (इसलिए आप केवल **`bash`** का उपयोग करके reverse shell नहीं चला सकते)।

पिछले Sandbox bypass के बाद Microsoft ने `~/Library/LaunchAgents` में files लिखने का option disable कर दिया। हालांकि, यह पता चला कि यदि आप **zip file को Login Item** के रूप में रखते हैं, तो `Archive Utility` उसे उसके current location पर **unzip** कर देगा। इसलिए, क्योंकि default रूप से `~/Library` का `LaunchAgents` folder बनाया नहीं जाता, **`LaunchAgents/~$escape.plist` में plist को zip करना** और zip file को **`~/Library`** में रखना संभव था। Decompress होने पर यह persistence destination तक पहुंच जाती।

[**original report here**](https://objective-see.org/blog/blog_0x4B.html) देखें।<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(याद रखें कि पहले escape से Word ऐसी arbitrary files लिख सकता है जिनके नाम `~$` से शुरू होते हैं।)

हालांकि, पिछली technique की एक limitation थी: यदि **`~/Library/LaunchAgents`** folder मौजूद हो, क्योंकि किसी अन्य software ने उसे बनाया हो, तो यह fail हो जाती। इसलिए इसके लिए एक अलग Login Items chain खोजी गई।

एक attacker payload के साथ **`.bash_profile`** और **`.zshenv`** files बना सकता था और फिर उन्हें zip करके victims के user folder में **`~/~$escape.zip`** के रूप में **लिख** सकता था।

फिर zip file और **`Terminal`** app को **Login Items** में add किया जाता। जब user दोबारा login करता, तो zip file user की files में uncompressed होकर **`.bash_profile`** और **`.zshenv`** को overwrite कर देती और इसलिए terminal इनमें से एक file को execute करता (यह इस पर निर्भर करता है कि bash या zsh का उपयोग किया जा रहा है)।

[**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) देखें।<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Sandboxed processes से अन्य processes को **`open`** utility का उपयोग करके invoke करना अभी भी संभव है। इसके अलावा, ये processes अपने स्वयं के sandbox के **भीतर** run होंगे।

यह पता चला कि open utility में किसी app को **specific env** variables के साथ run करने के लिए **`--env`** option है। इसलिए, **sandbox** के **अंदर** किसी folder में **`.zshenv` file** बनाना और **`HOME` variable** को उस folder पर set करके `open` का उपयोग करते हुए `Terminal` app खोलना संभव था। इससे `.zshenv` file execute होती (किसी कारण से `__OSINSTALL_ENVIROMENT` variable को set करना भी आवश्यक था)।

[**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/) देखें।<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility **`--stdin`** param को भी support करती थी (और पिछले bypass के बाद `--env` का उपयोग करना संभव नहीं रहा)।

बात यह है कि भले ही **`python`** Apple द्वारा signed था, लेकिन **`quarantine`** attribute वाली script को यह **execute नहीं करेगा**। हालांकि, stdin से script pass करना संभव था, इसलिए यह check नहीं करेगा कि वह quarantined है या नहीं:

1. Arbitrary Python commands वाली **`~$exploit.py`** file drop करें।
2. _open_ **`–stdin='~$exploit.py' -a Python`** चलाएं, जो Python app को run करता है और हमारी dropped file को उसके standard input के रूप में उपयोग करता है। Python खुशी से हमारा code run करता है और, क्योंकि यह _launchd_ की child process है, इसलिए यह Word के sandbox rules से bound नहीं होती।

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
