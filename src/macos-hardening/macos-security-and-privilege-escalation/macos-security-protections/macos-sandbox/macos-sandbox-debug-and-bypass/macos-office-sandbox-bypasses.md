# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox omseiling via Launch Agents

Die toepassing gebruik 'n **aangepaste Sandbox** met die regte **`com.apple.security.temporary-exception.sbpl`** en hierdie aangepaste sandbox laat toe om lêers enige plek te skryf solank die lêernaam met `~$` begin: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Daarom was dit so maklik soos **om 'n `plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist` te skryf.

Kyk die [**oorspronklike verslag hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox omseiling via Login Items en zip

Onthou dat vanaf die eerste ontsnapping, Word willekeurige lêers kan skryf waarvan die naam met `~$` begin, alhoewel dit na die regstelling van die vorige kwesbaarheid nie moontlik was om in `/Library/Application Scripts` of in `/Library/LaunchAgents` te skryf nie.

Daar is ontdek dat dit vanuit die sandbox moontlik is om 'n **Login Item** (toepassings wat uitgevoer sal word wanneer die gebruiker aanmeld) te skep. Hierdie toepassings **sal egter nie uitgevoer word nie** tensy hulle **notarized** is en dit is **nie moontlik om args toe te voeg nie** (so jy kan nie net 'n omgekeerde shell met **`bash`** uitvoer nie).

Van die vorige Sandbox omseiling het Microsoft die opsie om lêers in `~/Library/LaunchAgents` te skryf, gedeaktiveer. Dit is egter ontdek dat as jy 'n **zip-lêer as 'n Login Item** plaas, die `Archive Utility` dit net **ontzip** op sy huidige ligging. So, omdat die gids `LaunchAgents` van `~/Library` nie standaard geskep word nie, was dit moontlik om 'n **plist in `LaunchAgents/~$escape.plist`** te **zip** en die zip-lêer in **`~/Library`** te **plaas** sodat wanneer dit ontzip word, dit die volhardingsbestemming sal bereik.

Kyk die [**oorspronklike verslag hier**](https://objective-see.org/blog/blog_0x4B.html).

### Word Sandbox omseiling via Login Items en .zshenv

(Onthou dat vanaf die eerste ontsnapping, Word willekeurige lêers kan skryf waarvan die naam met `~$` begin).

Die vorige tegniek het egter 'n beperking gehad; as die gids **`~/Library/LaunchAgents`** bestaan omdat 'n ander sagteware dit geskep het, sou dit misluk. 'n Ander Login Items-ketting is vir hierdie ontdek.

'n Aanvaller kan die lêers **`.bash_profile`** en **`.zshenv`** met die payload om uit te voer skep en dit dan zip en **die zip in die slagoffer** se gebruikersgids skryf: **`~/~$escape.zip`**.

Voeg dan die zip-lêer by die **Login Items** en dan die **`Terminal`** toepassing. Wanneer die gebruiker weer aanmeld, sal die zip-lêer in die gebruikerslêer ontplof, wat **`.bash_profile`** en **`.zshenv`** oorskryf en gevolglik sal die terminal een van hierdie lêers uitvoer (afhangende of bash of zsh gebruik word).

Kyk die [**oorspronklike verslag hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Omseiling met Open en omgewingsveranderlikes

Van sandboxed prosesse is dit steeds moontlik om ander prosesse aan te roep met die **`open`** nut. Boonop sal hierdie prosesse **binne hul eie sandbox** loop.

Daar is ontdek dat die open nut die **`--env`** opsie het om 'n toepassing met **spesifieke omgewings** veranderlikes te laat loop. Daarom was dit moontlik om die **`.zshenv` lêer** binne 'n gids **binne** die **sandbox** te skep en die gebruik van `open` met `--env` om die **`HOME` veranderlike** na daardie gids in te stel wat die `Terminal` toepassing sal oopmaak, wat die `.zshenv` lêer sal uitvoer (om 'n of ander rede was dit ook nodig om die veranderlike `__OSINSTALL_ENVIROMENT` in te stel).

Kyk die [**oorspronklike verslag hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Omseiling met Open en stdin

Die **`open`** nut het ook die **`--stdin`** param ondersteun (en na die vorige omseiling was dit nie meer moontlik om `--env` te gebruik nie).

Die ding is dat selfs al is **`python`** deur Apple gesertifiseer, dit **sal nie** 'n skrip met die **`quarantine`** attribuut uitvoer nie. Dit was egter moontlik om 'n skrip van stdin aan te bied sodat dit nie sal nagaan of dit gekwarantyn is of nie:&#x20;

1. Laat 'n **`~$exploit.py`** lêer met willekeurige Python-opdragte val.
2. Voer _open_ **`–stdin='~$exploit.py' -a Python`** uit, wat die Python-toepassing met ons gevalle lêer as sy standaard invoer laat loop. Python voer ons kode met vreugde uit, en aangesien dit 'n kind proses van _launchd_ is, is dit nie gebonde aan Word se sandbox reëls nie.

{{#include ../../../../../banners/hacktricks-training.md}}
