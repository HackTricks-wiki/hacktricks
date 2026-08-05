# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Launch Agents के माध्यम से Word Sandbox bypass

यह application entitlement **`com.apple.security.temporary-exception.sbpl`** का उपयोग करके एक **custom Sandbox** इस्तेमाल करती है और यह custom sandbox कहीं भी files लिखने की अनुमति देता है, जब तक filename की शुरुआत `~$` से होती है: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

इसलिए escaping उतना ही आसान था जितना `~/Library/LaunchAgents/~$escape.plist` में एक **`plist`** LaunchAgent लिखना।

[**original report यहां देखें**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)<sup>[1]</sup>

### Login Items और zip के माध्यम से Word Sandbox bypass

याद रखें कि पहले escape से Word ऐसी arbitrary files लिख सकता है जिनके नाम `~$` से शुरू होते हैं, हालांकि पिछली vuln के patch के बाद `/Library/Application Scripts` या `/Library/LaunchAgents` में लिखना संभव नहीं था।

यह पता चला कि sandbox के अंदर से एक **Login Item** (ऐसे apps जो user के login करने पर execute होते हैं) बनाया जा सकता है। हालांकि, ये apps **तब तक execute नहीं होंगे जब तक** वे **notarized** न हों और **args जोड़ना संभव नहीं है** (इसलिए आप केवल **`bash`** का उपयोग करके reverse shell नहीं चला सकते)।

पिछले Sandbox bypass के बाद Microsoft ने `~/Library/LaunchAgents` में files लिखने का option disable कर दिया। हालांकि, यह पता चला कि यदि आप एक **zip file को Login Item** के रूप में रखते हैं, तो `Archive Utility` उसे उसके current location पर **unzip** कर देगा। इसलिए, क्योंकि default रूप से `~/Library` का `LaunchAgents` folder बनाया नहीं जाता, `LaunchAgents/~$escape.plist` में एक **plist को zip** करना और उस zip file को **`~/Library`** में रखना संभव था, ताकि decompress होने पर वह persistence destination तक पहुंच जाए।

[**original report यहां देखें**](https://objective-see.org/blog/blog_0x4B.html)<sup>[2]</sup>

### Login Items और .zshenv के माध्यम से Word Sandbox bypass

(याद रखें कि पहले escape से Word ऐसी arbitrary files लिख सकता है जिनके नाम `~$` से शुरू होते हैं।)

हालांकि, पिछली technique की एक limitation थी: यदि **`~/Library/LaunchAgents`** folder मौजूद हो, क्योंकि किसी अन्य software ने उसे बनाया हो, तो यह fail हो जाती। इसलिए इसके लिए एक अलग Login Items chain खोजी गई।

एक attacker payload को execute करने के लिए **`.bash_profile`** और **`.zshenv`** files बना सकता था, फिर उन्हें zip करके victims के user folder में **`~/~$escape.zip`** के रूप में **write** कर सकता था।

फिर zip file और उसके बाद **`Terminal`** app को **Login Items** में add किया जाता। जब user दोबारा login करता, तो zip file users के file में uncompressed हो जाती, **`.bash_profile`** और **`.zshenv`** को overwrite कर देती और इसलिए terminal इनमें से एक file को execute करता (यह इस बात पर निर्भर करता है कि bash या zsh का उपयोग किया जा रहा है)।

[**original report यहां देखें**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)<sup>[3]</sup>

### Open और env variables के साथ Word Sandbox Bypass

Sandboxed processes से **`open`** utility का उपयोग करके अन्य processes को invoke करना अभी भी संभव है। इसके अलावा, ये processes अपने स्वयं के **sandbox** के अंदर run होंगे।

यह पता चला कि open utility में किसी app को **specific env** variables के साथ run करने के लिए **`--env`** option है। इसलिए, **sandbox** के अंदर किसी folder में **`.zshenv` file** बनाना और **`HOME` variable** को उस folder पर set करके `Terminal` app को खोलने के लिए `open` का उपयोग करना संभव था; इससे `.zshenv` file execute होती (किसी कारण से variable `__OSINSTALL_ENVIROMENT` को set करना भी आवश्यक था)।

[**original report यहां देखें**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)<sup>[4]</sup>

### Open और stdin के साथ Word Sandbox Bypass

**`open`** utility **`--stdin`** param को भी support करती थी (और पिछले bypass के बाद `--env` का उपयोग करना संभव नहीं रहा)।

बात यह है कि भले ही **`python`** Apple द्वारा signed था, फिर भी वह **`quarantine`** attribute वाली script को **execute नहीं करेगा**। हालांकि, stdin से उसे एक script pass करना संभव था, इसलिए वह यह check नहीं करता था कि script quarantined है या नहीं:

1. Arbitrary Python commands वाली **`~$exploit.py`** file drop करें।
2. _open_ **`–stdin='~$exploit.py' -a Python`** run करें, जो Python app को हमारी dropped file को standard input के रूप में उपयोग करके run करता है। Python खुशी से हमारे code को run करता है और, क्योंकि यह _launchd_ की child process है, इसलिए यह Word के sandbox rules से bound नहीं होती।

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
