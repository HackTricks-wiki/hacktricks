# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Programu inatumia **custom Sandbox** kwa kutumia ruhusa **`com.apple.security.temporary-exception.sbpl`** na sandbox hii ya kawaida inaruhusu kuandika faili popote mradi jina la faili lianze na `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Hivyo, kutoroka ilikuwa rahisi kama **kuandika `plist`** LaunchAgent katika `~/Library/LaunchAgents/~$escape.plist`.

Angalia [**ripoti ya asili hapa**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

Kumbuka kwamba kutoka kwa kutoroka kwanza, Word inaweza kuandika faili za kawaida ambazo jina lake linaanza na `~$` ingawa baada ya patch ya vuln iliyopita haikuwezekana kuandika katika `/Library/Application Scripts` au katika `/Library/LaunchAgents`.

Iligundulika kwamba kutoka ndani ya sandbox inawezekana kuunda **Login Item** (programu ambazo zitatekelezwa wakati mtumiaji anapoingia). Hata hivyo, programu hizi **hazitaweza kutekelezwa isipokuwa** zime **notarized** na **haiwezekani kuongeza args** (hivyo huwezi tu kuendesha shell ya kinyume kwa kutumia **`bash`**).

Kutoka kwa kutoroka kwa Sandbox iliyopita, Microsoft ilizima chaguo la kuandika faili katika `~/Library/LaunchAgents`. Hata hivyo, iligundulika kwamba ikiwa utaweka **faili ya zip kama Login Item** `Archive Utility` itachambua tu **zip** katika eneo lake la sasa. Hivyo, kwa sababu kwa kawaida folda `LaunchAgents` kutoka `~/Library` haijaundwa, ilikuwa inawezekana **kuzipa plist katika `LaunchAgents/~$escape.plist`** na **kuiweka** faili ya zip katika **`~/Library`** ili wakati wa kufungua itafikia mahali pa kudumu.

Angalia [**ripoti ya asili hapa**](https://objective-see.org/blog/blog_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(Kumbuka kwamba kutoka kwa kutoroka kwanza, Word inaweza kuandika faili za kawaida ambazo jina lake linaanza na `~$`).

Hata hivyo, mbinu iliyopita ilikuwa na kikomo, ikiwa folda **`~/Library/LaunchAgents`** ipo kwa sababu programu nyingine iliiunda, ingekuwa na makosa. Hivyo, mnyororo tofauti wa Login Items uligundulika kwa hili.

Mshambuliaji angeweza kuunda faili **`.bash_profile`** na **`.zshenv`** zikiwa na payload ya kutekeleza na kisha kuzipa na **kuandika zip katika** folda ya mtumiaji wa wahanga: **`~/~$escape.zip`**.

Kisha, ongeza faili ya zip kwenye **Login Items** na kisha programu ya **`Terminal`**. Wakati mtumiaji anapoingia tena, faili ya zip itafunguliwa katika faili za watumiaji, ikipunguza **`.bash_profile`** na **`.zshenv`** na hivyo, terminal itatekeleza moja ya faili hizi (kulingana na ikiwa bash au zsh inatumika).

Angalia [**ripoti ya asili hapa**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

Kutoka kwa michakato ya sandboxed bado inawezekana kuita michakato mingine kwa kutumia **`open`** utility. Zaidi ya hayo, michakato hii itakimbia **ndani ya sandbox yao wenyewe**.

Ilipatikana kwamba utility ya open ina chaguo la **`--env`** kuendesha programu na **mabadiliko maalum**. Hivyo, ilikuwa inawezekana kuunda **faili ya `.zshenv`** ndani ya folda **ndani** ya **sandbox** na kutumia `open` na `--env` kuweka **`HOME` variable** kwa folda hiyo ikifungua programu hiyo ya `Terminal`, ambayo itatekeleza faili ya `.zshenv` (kwa sababu fulani ilikuwa pia inahitajika kuweka variable `__OSINSTALL_ENVIROMENT`).

Angalia [**ripoti ya asili hapa**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

Utility ya **`open`** pia ilisaidia param ya **`--stdin`** (na baada ya kutoroka kwa awali haikuwezekana tena kutumia `--env`).

Jambo ni kwamba hata kama **`python`** ilitiwa saini na Apple, haitatekeleza **script** yenye sifa ya **`quarantine`**. Hata hivyo, ilikuwa inawezekana kuipatia script kutoka stdin hivyo haitakagua ikiwa ilikuwa imewekwa karantini au la:&#x20;

1. Angusha faili **`~$exploit.py`** yenye amri za Python za kawaida.
2. Kimbia _open_ **`–stdin='~$exploit.py' -a Python`**, ambayo inakimbia programu ya Python na faili yetu iliyotupwa ikihudumu kama ingizo lake la kawaida. Python kwa furaha inakimbia msimbo wetu, na kwa kuwa ni mchakato wa mtoto wa _launchd_, haifungwi na sheria za sandbox za Word.

{{#include ../../../../../banners/hacktricks-training.md}}
