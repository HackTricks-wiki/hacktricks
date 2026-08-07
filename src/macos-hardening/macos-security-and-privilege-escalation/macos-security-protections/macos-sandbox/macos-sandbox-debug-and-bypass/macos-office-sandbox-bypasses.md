# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

यह application entitlement **`com.apple.security.temporary-exception.sbpl`** का उपयोग करके एक **custom Sandbox** इस्तेमाल करती है और यह custom sandbox कहीं भी files write करने की अनुमति देता है, जब तक filename `~$` से शुरू हो: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

इसलिए escape करना उतना ही आसान था जितना **`~/Library/LaunchAgents/~$escape.plist`** में एक **`plist`** LaunchAgent **write** करना।

[**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) देखें।<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

याद रखें कि पहले escape से Word ऐसी arbitrary files write कर सकता है जिनके नाम `~$` से शुरू होते हैं, हालांकि पिछली vuln के patch के बाद `/Library/Application Scripts` या `/Library/LaunchAgents` में write करना संभव नहीं था।

यह पता चला कि sandbox के अंदर से एक **Login Item** (ऐसी apps जो user के login करने पर execute होंगी) create करना संभव है। हालांकि, ये apps **तब तक execute नहीं होंगी जब तक** वे **notarized** न हों और **args add करना संभव नहीं है** (इसलिए आप केवल **`bash`** का उपयोग करके reverse shell run नहीं कर सकते)।

पिछले Sandbox bypass के बाद Microsoft ने `~/Library/LaunchAgents` में files write करने का option disable कर दिया। हालांकि, यह पता चला कि यदि आप एक **zip file को Login Item** के रूप में रखते हैं, तो `Archive Utility` उसे उसके current location पर **unzip** कर देगा। इसलिए, क्योंकि default रूप से `~/Library` का `LaunchAgents` folder create नहीं होता, **`LaunchAgents/~$escape.plist` में एक plist को zip करना** और उस **zip** file को **`~/Library`** में रखना संभव था, ताकि decompress होने पर वह persistence destination तक पहुंच जाए।

[**original report here**](https://objective-see.org/blog/blog_0x4B.html) देखें।<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(याद रखें कि पहले escape से Word ऐसी arbitrary files write कर सकता है जिनके नाम `~$` से शुरू होते हैं।)

हालांकि, पिछली technique की एक limitation थी: यदि **`~/Library/LaunchAgents`** folder मौजूद हो, क्योंकि किसी अन्य software ने उसे create किया हो, तो यह fail हो जाती। इसलिए इसके लिए एक अलग Login Items chain discover की गई।

एक attacker payload के साथ **`.bash_profile`** और **`.zshenv`** files create कर सकता था, फिर उन्हें zip करके victims के user folder में **`~/~$escape.zip`** के रूप में **write** कर सकता था।

फिर, zip file और उसके बाद **`Terminal`** app को **Login Items** में add करें। जब user दोबारा login करेगा, तो zip file user की files में uncompressed हो जाएगी और **`.bash_profile`** तथा **`.zshenv`** को overwrite कर देगी; इसलिए terminal इनमें से एक file execute करेगा (यह इस पर निर्भर करता है कि `bash` या `zsh` का उपयोग किया जा रहा है)।

[**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) देखें।<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Sandboxed processes से **`open`** utility का उपयोग करके अन्य processes invoke करना अभी भी संभव है। इसके अलावा, ये processes अपने स्वयं के sandbox के अंदर run होंगी।

यह पता चला कि open utility में **`--env`** option है, जो किसी app को **specific env** variables के साथ run करने देता है। इसलिए, **sandbox** के अंदर किसी folder में **`.zshenv` file** create करना और `--env` के साथ `open` का उपयोग करके **`HOME` variable** को उस folder पर set करते हुए `Terminal` app open करना संभव था; इससे `.zshenv` file execute होगी (किसी कारण से variable `__OSINSTALL_ENVIROMENT` को set करना भी आवश्यक था)।

[**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/) देखें।<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility **`--stdin`** param को भी support करती थी (और पिछले bypass के बाद `--env` का उपयोग करना संभव नहीं रहा)।

बात यह है कि भले ही **`python`** Apple द्वारा signed था, फिर भी वह **`quarantine`** attribute वाली script को **execute नहीं करेगा**। हालांकि, stdin से उसे एक script pass करना संभव था, जिससे वह यह check नहीं करेगा कि वह quarantined है या नहीं:

1. arbitrary Python commands वाली **`~$exploit.py`** file drop करें।
2. _open_ **`–stdin='~$exploit.py' -a Python`** run करें, जो Python app को हमारी dropped file को standard input के रूप में उपयोग करके run करता है। Python खुशी से हमारे code को run करता है और, क्योंकि यह _launchd_ की child process है, यह Word के sandbox rules से bound नहीं होता।<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
