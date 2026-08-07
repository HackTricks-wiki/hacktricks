# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Application hutumia **custom Sandbox** kwa kutumia entitlement **`com.apple.security.temporary-exception.sbpl`**, na custom sandbox hii inaruhusu kuandika files popote mradi jina la file lianze na `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Kwa hiyo, escaping ilikuwa rahisi kama **kuandika `plist`** LaunchAgent katika `~/Library/LaunchAgents/~$escape.plist`.

Angalia [**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

Kumbuka kwamba kutoka kwenye escape ya kwanza, Word inaweza kuandika arbitrary files ambayo majina yake yanaanza na `~$`, ingawa baada ya patch ya vuln ya awali haikuwezekana kuandika katika `/Library/Application Scripts` au `/Library/LaunchAgents`.

Iligunduliwa kwamba kutoka ndani ya sandbox inawezekana kuunda **Login Item** (apps zitakazoendeshwa mtumiaji anapo-login). Hata hivyo, apps hizi **hazita-execute isipokuwa** ziwe **notarized**, na **haiwezekani kuongeza args** (kwa hiyo huwezi ku-run reverse shell kwa kutumia **`bash`** tu).

Kutoka kwenye Sandbox bypass ya awali, Microsoft ilizima uwezo wa kuandika files katika `~/Library/LaunchAgents`. Hata hivyo, iligunduliwa kwamba ukiweka **zip file kama Login Item**, `Archive Utility` ita-**unzip** katika location yake ya sasa. Kwa hiyo, kwa sababu kwa default folder `LaunchAgents` kutoka `~/Library` haijaumbwa, iliwezekana **ku-zip plist katika `LaunchAgents/~$escape.plist`** na **kuweka** zip file katika **`~/Library`**, ili inapodecompress kufikia persistence destination.

Angalia [**original report here**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Kumbuka kwamba kutoka kwenye escape ya kwanza, Word inaweza kuandika arbitrary files ambayo majina yake yanaanza na `~$`).

Hata hivyo, technique ya awali ilikuwa na limitation: ikiwa folder **`~/Library/LaunchAgents`** ipo kwa sababu software nyingine iliiumba, ingefeli. Kwa hiyo, Login Items chain tofauti iligunduliwa kwa ajili ya hili.

Attacker angeweza kuunda files **`.bash_profile`** na **`.zshenv`** zikiwa na payload ya ku-execute, kisha azip- na **kuandika zip katika** user folder ya **victim**: **`~/~$escape.zip`**.

Kisha, ongeza zip file kwenye **Login Items**, pamoja na **`Terminal`** app. Mtumiaji atakapo-login tena, zip file inge-uncompressed katika user folder, iki-overwrite **`.bash_profile`** na **`.zshenv`**, na kwa hiyo terminal inge-execute moja ya files hizi (kulingana na kama bash au zsh inatumika).

Angalia [**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Kutoka kwenye sandboxed processes bado inawezekana ku-invoke processes nyingine kwa kutumia **`open`** utility. Zaidi ya hayo, processes hizi zita-run **ndani ya sandbox yao wenyewe**.

Iligunduliwa kwamba open utility ina option ya **`--env`** ya ku-run app ikiwa na **specific env** variables. Kwa hiyo, iliwezekana kuunda **`.zshenv` file** ndani ya folder **iliyo ndani ya** **sandbox**, kisha kutumia `open` ikiwa na `--env` ikiset **`HOME` variable** kuwa folder hiyo na kufungua `Terminal` app, ambayo inge-execute `.zshenv` file (kwa sababu fulani ilihitajika pia kuset variable `__OSINSTALL_ENVIROMENT`).

Angalia [**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility pia ili-support **`--stdin`** param (na baada ya bypass ya awali haikuwezekana tena kutumia `--env`).

Jambo ni kwamba hata kama **`python`** ilikuwa signed na Apple, **haita-execute** script yenye attribute ya **`quarantine`**. Hata hivyo, iliwezekana kuipatia script kupitia stdin, hivyo isinge-check kama ilikuwa quarantined au la:

1. Drop file ya **`~$exploit.py`** yenye arbitrary Python commands.
2. Run _open_ **`–stdin='~$exploit.py' -a Python`**, ambayo ina-run Python app huku file yetu tulilodrop likitumika kama standard input. Python ina-run code yetu bila tatizo, na kwa kuwa ni child process ya _launchd_, haifungwi na sheria za Word za sandbox.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
