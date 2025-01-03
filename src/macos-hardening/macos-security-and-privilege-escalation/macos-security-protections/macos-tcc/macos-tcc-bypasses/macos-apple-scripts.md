# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Dit is 'n skriptaal wat gebruik word vir taakautomatisering **wat met afstandsprosesse interaksie het**. Dit maak dit redelik maklik om **ander prosesse te vra om sekere aksies uit te voer**. **Malware** kan hierdie funksies misbruik om funksies wat deur ander prosesse uitgevoer word, te misbruik.\
Byvoorbeeld, 'n malware kan **arbitraire JS-kode in blaaiers wat oopgemaak is, inspuit**. Of **outomaties op klik** op sommige toestemmings wat aan die gebruiker gevra word;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hier is 'n paar voorbeelde: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Vind meer inligting oor malware wat met applescripts werk [**hier**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple skripte kan maklik "**gecompileer**" word. Hierdie weergawes kan maklik "**gedecompileer**" word met `osadecompile`

However, this scripts can also be **exported as "Read only"** (via the "Export..." option):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
en in hierdie geval kan die inhoud nie gedekompileer word nie, selfs nie met `osadecompile` nie.

Daar is egter steeds 'n paar gereedskap wat gebruik kan word om hierdie soort uitvoerbare lêers te verstaan, [**lees hierdie navorsing vir meer inligting**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Die gereedskap [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) met [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) sal baie nuttig wees om te verstaan hoe die skrip werk.

{{#include ../../../../../banners/hacktricks-training.md}}
