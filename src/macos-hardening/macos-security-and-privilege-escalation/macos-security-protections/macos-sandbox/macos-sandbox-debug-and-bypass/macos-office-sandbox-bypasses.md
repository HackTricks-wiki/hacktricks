# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

निम्नलिखित **Microsoft Office for Mac sandbox escapes** के ऐतिहासिक उदाहरण हैं। ये दोबारा उपयोग की जा सकने वाली trust-boundary गलतियों को दर्ज करते हैं, लेकिन exact version और policy को दोबारा जांचे बिना patched Office/macOS combinations को vulnerable नहीं मानना चाहिए।

### Word sandbox bypass via LaunchAgents

प्रभावित application ने `com.apple.security.temporary-exception.sbpl` के माध्यम से एक custom sandbox rule का उपयोग किया। इसने उन regular files को अनुमति दी जिनका basename `~$` से शुरू होता था: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

इसलिए escaping केवल `~/Library/LaunchAgents/~$escape.plist` में एक **`plist`** LaunchAgent **लिखने** जितना आसान था।

[**original report यहां देखें**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

याद रखें कि पहले escape से Word ऐसी arbitrary files लिख सकता है जिनके नाम `~$` से शुरू होते हैं, हालांकि पिछली vuln के patch के बाद `/Library/Application Scripts` या `/Library/LaunchAgents` में लिखना संभव नहीं था।

प्रभावित sandbox ने एक **Login Item** बनाने की अनुमति दी, जो user के login करने पर launch होता है। प्रदर्शित path के लिए एक स्वीकार्य signed/notarized application आवश्यक थी और arbitrary arguments की अनुमति नहीं थी, इसलिए reverse-shell argument के साथ `bash` जोड़ना पर्याप्त नहीं था।<sup>[[2]](#references)</sup>

पिछले Sandbox bypass के बाद Microsoft ने `~/Library/LaunchAgents` में files लिखने का option disable कर दिया। हालांकि, यह पता चला कि यदि आप एक **zip file को Login Item** के रूप में रखते हैं, तो `Archive Utility` उसे उसके current location पर **unzip** कर देता है। इसलिए, क्योंकि default रूप से `~/Library` का `LaunchAgents` folder बनाया नहीं जाता, **`LaunchAgents/~$escape.plist` में एक plist को zip करना** और उस zip file को **`~/Library`** में **रखना** संभव था, ताकि decompress होने पर वह persistence destination तक पहुंच जाए।

[**original report यहां देखें**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(याद रखें कि पहले escape से Word ऐसी arbitrary files लिख सकता है जिनके नाम `~$` से शुरू होते हैं।)

हालांकि, पिछली technique की एक limitation थी: यदि **`~/Library/LaunchAgents`** folder मौजूद हो, क्योंकि किसी अन्य software ने उसे बनाया हो, तो यह fail हो जाती थी। इसलिए इसके लिए एक अलग Login Items chain खोजी गई।

Attacker payload वाले **`.bash_profile`** और **`.zshenv`** बना सकता था, उन्हें archive कर सकता था और ZIP को **victim** की home directory में **`~/~$escape.zip`** के रूप में लिख सकता था।

फिर ZIP और **Terminal** को Login Items के रूप में जोड़ें। अगले login पर Archive Utility dotfiles को user की home directory में extract करता है और Terminal का shell लागू startup file evaluate करता है (`.bash_profile` demonstrated Bash path के लिए या `.zshenv` Zsh के लिए)।<sup>[[3]](#references)</sup>

[**original report यहां देखें**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Sandboxed processes अभी भी **`open`** के माध्यम से application launches request कर सकते थे। Launched application अपने security context में चलती थी, Word के exact sandbox profile को inherit करने के बजाय।<sup>[[4]](#references)</sup>

प्रभावित `open` utility में environment variables देने के लिए **`--env`** option था। Exploit ने sandbox के अंदर `.zshenv` बनाया, `HOME` को उस directory पर set किया और Terminal launch किया, ताकि Zsh उसे evaluate करे। Report की गई chain ने misspelled private variable `__OSINSTALL_ENVIROMENT` भी set किया था; historical PoC को reproduce करते समय यही exact spelling रखें।<sup>[[4]](#references)</sup>

[**original report यहां देखें**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility **`--stdin`** param को भी support करती थी (और पिछले bypass के बाद `--env` का उपयोग करना संभव नहीं था)।

हालांकि Apple's Python application quarantined script file को reject कर देती थी, vulnerable workflow उसी script को standard input के माध्यम से feed कर सकता था, जिससे file-based quarantine check से बचा जा सकता था:<sup>[[5]](#references)</sup>

1. Arbitrary Python commands वाली **`~$exploit.py`** file drop करें।
2. `open --stdin='~$exploit.py' -a Python` चलाएं। Launched Python application dropped code को standard input पर प्राप्त करती है और vulnerable versions में Word के sandbox के बाहर चलती है, क्योंकि LaunchServices इसे `launchd` के अंतर्गत create करता है।<sup>[[5]](#references)</sup>

## References

- [1] [Sandbox से escape – macOS पर Microsoft Office](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [macOS पर Office Drama](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [CVE-2021-30864 का Technical Analysis](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [macOS App Sandbox escape vulnerability का पता लगाना: CVE-2022-26706 का विस्तृत विश्लेषण - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
