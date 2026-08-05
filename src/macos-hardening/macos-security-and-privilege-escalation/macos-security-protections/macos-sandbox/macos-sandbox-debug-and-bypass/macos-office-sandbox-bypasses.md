# Word Sandbox Bypass za macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass kupitia Launch Agents

Programu hutumia **custom Sandbox** kwa kutumia entitlement **`com.apple.security.temporary-exception.sbpl`**, na custom sandbox hii inaruhusu kuandika files popote mradi tu jina la file lianze na `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Kwa hiyo, kutoroka kulikuwa rahisi kama **kuandika `plist`** ya LaunchAgent katika `~/Library/LaunchAgents/~$escape.plist`.

Angalia [**ripoti ya awali hapa**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[1]</sup>

### Word Sandbox bypass kupitia Login Items na zip

Kumbuka kwamba baada ya escape ya kwanza, Word inaweza kuandika files holela ambayo majina yake yanaanza na `~$`, ingawa baada ya patch ya vuln ya awali haikuwezekana kuandika katika `/Library/Application Scripts` au `/Library/LaunchAgents`.

Iligunduliwa kwamba kutoka ndani ya sandbox inawezekana kuunda **Login Item** (apps zitakazoendeshwa mtumiaji anapoingia). Hata hivyo, apps hizi **hazitaendeshwa isipokuwa** ziwe **notarized**, na **haiwezekani kuongeza args** (kwa hiyo huwezi kuendesha reverse shell kwa kutumia **`bash`** tu).

Kutokana na Sandbox bypass ya awali, Microsoft ilizima chaguo la kuandika files katika `~/Library/LaunchAgents`. Hata hivyo, iligunduliwa kwamba ukiweka **zip file kama Login Item**, `Archive Utility` ita **unzip** tu katika eneo lake la sasa. Kwa hiyo, kwa kuwa kwa default folder ya `LaunchAgents` kutoka `~/Library` haijaundwa, iliwezekana **kuzip plist katika `LaunchAgents/~$escape.plist`** na **kuweka** zip file katika **`~/Library`**, ili itakapodecompress kufikia eneo la persistence.

Angalia [**ripoti ya awali hapa**](https://objective-see.org/blog/blog_0x4B.html).<sup>[2]</sup>

### Word Sandbox bypass kupitia Login Items na .zshenv

(Kumbuka kwamba baada ya escape ya kwanza, Word inaweza kuandika files holela ambayo majina yake yanaanza na `~$`).

Hata hivyo, technique ya awali ilikuwa na limitation: ikiwa folder **`~/Library/LaunchAgents`** ipo kwa sababu software nyingine iliunda folder hiyo, ingeshindwa. Kwa hiyo, chain tofauti ya Login Items iligunduliwa kwa ajili ya hali hii.

Attacker angeweza kuunda files **`.bash_profile`** na **`.zshenv`** zikiwa na payload ya ku-execute, kisha kuzip na **kuandika zip katika folder ya user ya victim**: **`~/~$escape.zip`**.

Kisha, ongeza zip file kwenye **Login Items** pamoja na app ya **`Terminal`**. Mtumiaji atakapoingia tena, zip file inge-uncompress katika folder ya user, iki-overwrite **`.bash_profile`** na **`.zshenv`**, na kwa hiyo terminal inge-execute mojawapo ya files hizi (kutegemea kama bash au zsh inatumika).

Angalia [**ripoti ya awali hapa**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[3]</sup>

### Word Sandbox Bypass kwa Open na env variables

Kutoka kwenye sandboxed processes bado inawezekana ku-invoke processes nyingine kwa kutumia utility ya **`open`**. Zaidi ya hayo, processes hizi zita-run **ndani ya sandbox yao wenyewe**.

Iligunduliwa kwamba utility ya open ina option ya **`--env`** ya ku-run app ikiwa na **specific env** variables. Kwa hiyo, iliwezekana kuunda **`.zshenv file`** ndani ya folder **iliyo ndani** ya **sandbox**, kisha kutumia `open` yenye `--env` kuweka variable ya **`HOME`** kwenye folder hiyo na kufungua app ya `Terminal`, ambayo ita-execute file ya `.zshenv` (kwa sababu fulani ilihitajika pia kuweka variable `__OSINSTALL_ENVIROMENT`).

Angalia [**ripoti ya awali hapa**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[4]</sup>

### Word Sandbox Bypass kwa Open na stdin

Utility ya **`open`** pia iliunga mkono param ya **`--stdin`** (na baada ya bypass ya awali haikuwezekana tena kutumia `--env`).

Jambo ni kwamba hata kama **`python`** ilikuwa signed na Apple, **haita-execute** script yenye attribute ya **`quarantine`**. Hata hivyo, iliwezekana kuipatia script kupitia stdin, hivyo isinge-check kama ilikuwa quarantined au la:

1. Drop file ya **`~$exploit.py`** iliyo na arbitrary Python commands.
2. Run _open_ **`–stdin='~$exploit.py' -a Python`**, ambayo ina-run Python app huku file tulilodrop likitumika kama standard input yake. Python ina-run code yetu bila shida, na kwa kuwa ni child process ya _launchd_, haifungwi na rules za Word za sandbox.

## References

- [1] [Kutoroka Sandbox – Microsoft Office kwenye macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama kwenye macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
