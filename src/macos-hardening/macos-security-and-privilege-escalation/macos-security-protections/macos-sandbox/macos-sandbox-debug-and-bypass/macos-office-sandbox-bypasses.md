# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Die volgende is **historiese Microsoft Office for Mac sandbox escapes**. Hulle dokumenteer herbruikbare trust-boundary-foute, maar daar moet nie aanvaar word dat gepatchte Office/macOS-kombinasies kwesbaar is sonder om die presiese weergawe en beleid te reproduseer nie.

### Word sandbox bypass via LaunchAgents

Die betrokke toepassing het 'n pasgemaakte sandbox-reël deur middel van `com.apple.security.temporary-exception.sbpl` gebruik. Dit het gewone lêers toegelaat waarvan die basename met `~$` begin het: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Daarom was escaping so eenvoudig soos om 'n **`plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist` te **skryf**.

Sien die [**oorspronklike verslag hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items en zip

Onthou dat Word vanaf die eerste escape arbitrêre lêers kan skryf waarvan die name met `~$` begin, hoewel dit ná die patch van die vorige vuln nie moontlik was om in `/Library/Application Scripts` of `/Library/LaunchAgents` te skryf nie.

Die betrokke sandbox het die skepping van 'n **Login Item** toegelaat, wat geloods word wanneer die gebruiker aanmeld. Die gedemonstreerde pad het 'n aanvaarbaar ondertekende/gemagtigde toepassing vereis en het nie arbitrêre argumente toegelaat nie, dus was die byvoeging van `bash` met 'n reverse-shell-argument onvoldoende.<sup>[[2]](#references)</sup>

Vanaf die vorige Sandbox bypass het Microsoft die opsie gedeaktiveer om lêers in `~/Library/LaunchAgents` te skryf. Daar is egter ontdek dat, indien jy 'n **zip-lêer as 'n Login Item** plaas, die `Archive Utility` dit eenvoudig op sy huidige ligging sal **unzip**. Omdat die `LaunchAgents`-lêergids uit `~/Library` by verstek nie geskep word nie, was dit dus moontlik om 'n **plist in `LaunchAgents/~$escape.plist` te zip** en die zip-lêer in **`~/Library`** te **plaas**, sodat dit die persistence-bestemming bereik wanneer dit gedekomprimeer word.

Sien die [**oorspronklike verslag hier**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items en .zshenv

(Onthou dat Word vanaf die eerste escape arbitrêre lêers kan skryf waarvan die name met `~$` begin.)

Die vorige tegniek het egter 'n beperking gehad: indien die **`~/Library/LaunchAgents`**-lêergids bestaan omdat ander sagteware dit geskep het, sou dit misluk. Daarom is 'n ander Login Items-ketting hiervoor ontdek.

'n Aanvaller kon **`.bash_profile`** en **`.zshenv`** skep wat die payload bevat, dit argiveer en die ZIP na die **slagoffer se** home directory skryf as **`~/~$escape.zip`**.

Voeg dan die ZIP en **Terminal** as Login Items by. By die volgende aanmelding onttrek Archive Utility die dotfiles na die gebruiker se home directory, en Terminal se shell evalueer die toepaslike startup-lêer (`.bash_profile` vir die gedemonstreerde Bash-pad of `.zshenv` vir Zsh).<sup>[[3]](#references)</sup>

Sien die [**oorspronklike verslag hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open en env variables

Sandboxed prosesse kon steeds toepassing-launches deur middel van **`open`** aanvra. Die geloodsde toepassing het in sy eie security context geloop eerder as om Word se presiese sandbox-profiel te erf.<sup>[[4]](#references)</sup>

Die betrokke `open`-utility het 'n **`--env`**-opsie gehad om environment variables te verskaf. Die exploit het `.zshenv` binne die sandbox geskep, `HOME` na daardie directory gestel en Terminal geloods sodat Zsh dit evalueer. Die gerapporteerde ketting het ook die verkeerd gespelde private variable `__OSINSTALL_ENVIROMENT` gestel; behou daardie presiese spelling wanneer die historiese PoC gereproduseer word.<sup>[[4]](#references)</sup>

Sien die [**oorspronklike verslag hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open en stdin

Die **`open`**-utility het ook die **`--stdin`**-param ondersteun (en ná die vorige bypass was dit nie meer moontlik om `--env` te gebruik nie).

Hoewel Apple se Python application 'n quarantined script file sou verwerp, kon die kwesbare workflow dieselfde script oor standard input voer en sodoende die file-based quarantine check vermy:<sup>[[5]](#references)</sup>

1. Drop 'n **`~$exploit.py`**-lêer met arbitrêre Python commands.
2. Run `open --stdin='~$exploit.py' -a Python`. Die geloodsde Python application ontvang die gedropte code op standard input en, in die kwesbare weergawes, loop dit buite Word se sandbox omdat LaunchServices dit onder `launchd` skep.<sup>[[5]](#references)</sup>

## References

- [1] [Ontsnap uit die Sandbox – Microsoft Office op macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama op macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Tegniese ontleding van CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Onthulling van 'n macOS App Sandbox escape-kwesbaarheid: 'n diepgaande ondersoek van CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
