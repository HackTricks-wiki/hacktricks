# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Die toepassing gebruik 'n **custom Sandbox** met die entitlement **`com.apple.security.temporary-exception.sbpl`**, en hierdie custom sandbox laat toe dat lêers enige plek geskryf word solank die lêernaam met `~$` begin: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Daarom was escaping so eenvoudig soos om 'n **`plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist` te skryf.

Sien die [**oorspronklike verslag hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

Onthou dat Word vanaf die eerste escape arbitrêre lêers kan skryf waarvan die naam met `~$` begin, alhoewel dit ná die patch van die vorige vuln nie moontlik was om in `/Library/Application Scripts` of in `/Library/LaunchAgents` te skryf nie.

Daar is ontdek dat dit vanuit die sandbox moontlik is om 'n **Login Item** te skep (apps wat uitgevoer sal word wanneer die user aanmeld). Hierdie apps **sal egter nie uitgevoer word tensy** hulle **genotariseer** is nie, en dit is **nie moontlik om args by te voeg nie** (jy kan dus nie net 'n reverse shell met **`bash`** uitvoer nie).

Vanaf die vorige Sandbox bypass het Microsoft die opsie gedeaktiveer om lêers in `~/Library/LaunchAgents` te skryf. Daar is egter ontdek dat indien jy 'n **zip file as 'n Login Item** plaas, die `Archive Utility` dit eenvoudig op sy huidige ligging sal **unzip**. Omdat die `LaunchAgents`-folder uit `~/Library` by verstek nie geskep word nie, was dit dus moontlik om 'n **plist in `LaunchAgents/~$escape.plist` te zip** en die **zip file in `~/Library`** te plaas, sodat dit tydens decompression die persistence-bestemming bereik.

Sien die [**oorspronklike verslag hier**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Onthou dat Word vanaf die eerste escape arbitrêre lêers kan skryf waarvan die naam met `~$` begin.)

Die vorige tegniek het egter 'n beperking gehad: indien die folder **`~/Library/LaunchAgents`** bestaan omdat ander software dit geskep het, sou dit misluk. Daarom is 'n ander Login Items-chain hiervoor ontdek.

'n Attacker kon die lêers **`.bash_profile`** en **`.zshenv`** met die payload om uit te voer skep, dit dan zip en die zip in die victims se user-folder **`~/~$escape.zip`** skryf.

Voeg dan die zip file by die **Login Items** en daarna die **`Terminal`**-app. Wanneer die user weer aanmeld, sal die zip file in die user se folder uitgepak word, wat **`.bash_profile`** en **`.zshenv`** oorskryf. Die terminal sal gevolglik een van hierdie lêers uitvoer (afhangend van of bash of zsh gebruik word).

Sien die [**oorspronklike verslag hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Vanaf sandboxed processes is dit steeds moontlik om ander processes met die **`open`**-utility aan te roep. Hierdie processes sal boonop **binne hul eie sandbox** loop.

Daar is ontdek dat die open-utility die **`--env`**-opsie het om 'n app met **spesifieke env**-variables uit te voer. Dit was dus moontlik om die **`.zshenv`-file** binne 'n folder **in die** **sandbox** te skep en `open` met `--env` te gebruik om die **`HOME`-variable** na daardie folder te stel terwyl die `Terminal`-app oopgemaak word. Dit sal die `.zshenv`-file uitvoer (om een of ander rede was dit ook nodig om die variable `__OSINSTALL_ENVIROMENT` te stel).

Sien die [**oorspronklike verslag hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

Die **`open`**-utility het ook die **`--stdin`**-parameter ondersteun (en ná die vorige bypass was dit nie meer moontlik om `--env` te gebruik nie).

Die probleem is dat selfs al was **`python`** deur Apple gesign, dit **nie 'n script sal uitvoer** met die **`quarantine`**-attribute nie. Dit was egter moontlik om 'n script vanaf stdin aan dit deur te gee, sodat dit nie sou nagaan of dit in quarantine was nie:

1. Drop 'n **`~$exploit.py`**-file met arbitrêre Python commands.
2. Run _open_ **`–stdin='~$exploit.py' -a Python`**, wat die Python-app uitvoer met ons gedropte file as sy standard input. Python voer ons code sonder probleme uit, en omdat dit 'n child process van _launchd_ is, is dit nie aan Word se sandbox-reëls gebind nie.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
