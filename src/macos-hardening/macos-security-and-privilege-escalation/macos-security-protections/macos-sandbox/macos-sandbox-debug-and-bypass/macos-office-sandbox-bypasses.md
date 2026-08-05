# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass kupitia Launch Agents

Programu hutumia **custom Sandbox** kwa kutumia entitlement **`com.apple.security.temporary-exception.sbpl`**, na custom sandbox hii inaruhusu kuandika files popote mradi jina la file lianze na `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Kwa hiyo, escaping ilikuwa rahisi kama **kuandika `plist`** LaunchAgent katika `~/Library/LaunchAgents/~$escape.plist`.

Angalia [**ripoti ya awali hapa**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass kupitia Login Items na zip

Kumbuka kwamba baada ya escape ya kwanza, Word inaweza kuandika files kiholela ambayo majina yake yanaanza na `~$`, ingawa baada ya patch ya vuln ya awali haikuwezekana kuandika katika `/Library/Application Scripts` au `/Library/LaunchAgents`.

Iligunduliwa kwamba kutoka ndani ya sandbox inawezekana kuunda **Login Item** (apps zitakazoendeshwa mtumiaji anapoingia). Hata hivyo, apps hizi **hazitatekelezwa isipokuwa** ziwe **notarized**, na **haiwezekani kuongeza args** (kwa hiyo huwezi kuendesha reverse shell kwa kutumia **`bash`**).

Kutokana na Sandbox bypass ya awali, Microsoft ilizima uwezekano wa kuandika files katika `~/Library/LaunchAgents`. Hata hivyo, iligunduliwa kwamba ukiweka **zip file kama Login Item**, `Archive Utility` ita-**unzip** file hilo kwenye eneo lilipo. Kwa hiyo, kwa kuwa kwa default folder `LaunchAgents` kutoka `~/Library` haijaumbwi, iliwezekana **ku-zip plist katika `LaunchAgents/~$escape.plist`** na **kuweka** zip file katika **`~/Library`**, ili itakapodecompress kufikia eneo la persistence.

Angalia [**ripoti ya awali hapa**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass kupitia Login Items na .zshenv

(Kumbuka kwamba baada ya escape ya kwanza, Word inaweza kuandika files kiholela ambayo majina yake yanaanza na `~$`.)

Hata hivyo, technique ya awali ilikuwa na limitation: ikiwa folder **`~/Library/LaunchAgents`** ipo kwa sababu software nyingine iliiumba, ingeshindwa. Kwa hiyo, Login Items chain tofauti iligunduliwa kwa ajili ya hali hii.

Attacker angeweza kuunda files **`.bash_profile`** na **`.zshenv`** zikiwa na payload ya kutekelezwa, kisha kuz-zip na **kuandika zip hiyo katika folder la** user wa victim: **`~/~$escape.zip`**.

Kisha, ongeza zip file kwenye **Login Items** pamoja na app ya **`Terminal`**. Mtumiaji atakapoingia tena, zip file litadecompress katika folder la mtumiaji, na kubadilisha **`.bash_profile`** na **`.zshenv`**; kwa hiyo, terminal itatekeleza mojawapo ya files hizi (kulingana na kama bash au zsh inatumika).

Angalia [**ripoti ya awali hapa**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Kutoka kwa processes zilizo ndani ya sandbox bado inawezekana kuinvoke processes nyingine kwa kutumia utility ya **`open`**. Zaidi ya hayo, processes hizi zitaendeshwa **ndani ya sandbox yao wenyewe**.

Iligunduliwa kwamba open utility ina option ya **`--env`** ya kuendesha app yenye variables za **env** maalum. Kwa hiyo, iliwezekana kuunda **`.zshenv file`** ndani ya folder **iliyo ndani ya** **sandbox**, kisha kutumia `open` yenye `--env` kuweka variable ya **`HOME`** kwenye folder hilo na kufungua app ya `Terminal`, ambayo itatekeleza file la `.zshenv` (kwa sababu fulani ilihitajika pia kuweka variable `__OSINSTALL_ENVIROMENT`).

Angalia [**ripoti ya awali hapa**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

Utility ya **`open`** pia iliunga mkono param ya **`--stdin`** (na baada ya bypass ya awali haikuwezekana tena kutumia `--env`).

Jambo ni kwamba hata kama **`python`** ilikuwa signed na Apple, **haitatekeleza** script yenye attribute ya **`quarantine`**. Hata hivyo, iliwezekana kuipitishia script kupitia stdin, kwa hiyo haitakagua ikiwa ilikuwa quarantined au la:

1. Weka file la **`~$exploit.py`** lenye arbitrary Python commands.
2. Endesha _open_ **`–stdin='~$exploit.py' -a Python`**, ambayo huendesha Python app huku file letu lililowekwa likitumika kama standard input yake. Python hutekeleza code yetu bila tatizo, na kwa kuwa ni child process ya _launchd_, haifungwi na rules za Word sandbox.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
