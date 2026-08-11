# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Zifuatazo ni **historical Microsoft Office for Mac sandbox escapes**. Zinaonyesha makosa ya trust boundary yanayoweza kutumika tena, lakini mchanganyiko wa Office/macOS uliopigwa patch haupaswi kuchukuliwa kuwa vulnerable bila kuthibitisha toleo na policy husika.

### Word sandbox bypass kupitia LaunchAgents

Application iliyoathiriwa ilitumia sandbox rule maalum kupitia `com.apple.security.temporary-exception.sbpl`. Iliruhusu regular files ambazo basename yake ilianza na `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Kwa hiyo, escaping ilikuwa rahisi kama **kuandika `plist`** LaunchAgent ndani ya `~/Library/LaunchAgents/~$escape.plist`.

Tazama [**original report hapa**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass kupitia Login Items na zip

Kumbuka kwamba kutoka escape ya kwanza, Word inaweza kuandika arbitrary files ambazo majina yake yanaanza na `~$`, ingawa baada ya patch ya vuln ya awali haikuwezekana kuandika ndani ya `/Library/Application Scripts` au `/Library/LaunchAgents`.

Sandbox iliyoathiriwa iliruhusu kuundwa kwa **Login Item**, ambayo huanzishwa user anapo-login. Njia iliyoonyeshwa ilihitaji application yenye signature/notarization inayokubalika na haikuruhusu arbitrary arguments, hivyo kuongeza `bash` yenye reverse-shell argument hakukutosha.<sup>[[2]](#references)</sup>

Kutokana na Sandbox bypass ya awali, Microsoft ilizima option ya kuandika files ndani ya `~/Library/LaunchAgents`. Hata hivyo, iligunduliwa kwamba ukiweka **zip file kama Login Item**, `Archive Utility` ita**unzip** tu katika location yake ya sasa. Kwa hiyo, kwa kuwa kwa default folder ya `LaunchAgents` ndani ya `~/Library` haikuundwa, iliwezekana **ku-zip plist ndani ya `LaunchAgents/~$escape.plist`** na **kuweka** zip file ndani ya **`~/Library`**, ili wakati wa ku-decompress ifikie persistence destination.

Tazama [**original report hapa**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass kupitia Login Items na .zshenv

(Kumbuka kwamba kutoka escape ya kwanza, Word inaweza kuandika arbitrary files ambazo majina yake yanaanza na `~$`).

Hata hivyo, technique ya awali ilikuwa na limitation: ikiwa folder **`~/Library/LaunchAgents`** ipo kwa sababu software nyingine iliunda folder hiyo, ingeshindwa. Kwa hiyo, kwa ajili hii iligunduliwa Login Items chain tofauti.

Attacker angeweza kuunda **`.bash_profile`** na **`.zshenv`** zenye payload, kuzi-archive, na kuandika ZIP kwenye home directory ya **victim** kama **`~/~$escape.zip`**.

Kisha aongeze ZIP na **Terminal** kama Login Items. Wakati wa login inayofuata, Archive Utility hutoa dotfiles kwenye home directory ya user, na shell ya Terminal hutathmini startup file inayohusika (`.bash_profile` kwa Bash path iliyoonyeshwa au `.zshenv` kwa Zsh).<sup>[[3]](#references)</sup>

Tazama [**original report hapa**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Sandboxed processes bado zingeweza kuomba application launches kupitia **`open`**. Application iliyoanzishwa iliendesha katika security context yake badala ya kurithi exact sandbox profile ya Word.<sup>[[4]](#references)</sup>

`open` utility iliyoathiriwa ilikuwa na option ya **`--env`** kwa ajili ya kusupply environment variables. Exploit iliunda `.zshenv` ndani ya sandbox, ikaweka `HOME` kwenye directory hiyo, na ika-launch Terminal ili Zsh iitathmini. Chain iliyoripotiwa pia iliweka private variable iliyoandikwa vibaya `__OSINSTALL_ENVIROMENT`; hifadhi spelling hiyo exact wakati wa ku-reproduce historical PoC.<sup>[[4]](#references)</sup>

Tazama [**original report hapa**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

Utility ya **`open`** pia iliunga mkono param ya **`--stdin`** (na baada ya bypass ya awali haikuwezekana tena kutumia `--env`).

Ingawa Python application ya Apple ingekataa script file iliyo-quarantine, vulnerable workflow iliweza ku-feed script hiyo hiyo kupitia standard input, na hivyo kuepuka file-based quarantine check:<sup>[[5]](#references)</sup>

1. Drop **`~$exploit.py`** file yenye arbitrary Python commands.
2. Run `open --stdin='~$exploit.py' -a Python`. Python application iliyoanzishwa hupokea code iliyodropiwa kupitia standard input na, katika versions zilizo vulnerable, huendesha nje ya sandbox ya Word kwa sababu LaunchServices huiunda chini ya `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office kwenye macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama kwenye macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis ya CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Kufichua macOS App Sandbox escape vulnerability: Uchambuzi wa kina wa CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
