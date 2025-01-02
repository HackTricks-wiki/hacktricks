# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

To je jezik skriptinga koji se koristi za automatizaciju zadataka **interakcijom sa udaljenim procesima**. Omogućava prilično lako **traženje od drugih procesa da izvrše neke radnje**. **Malver** može zloupotrebiti ove funkcije da bi zloupotrebio funkcije koje izlažu drugi procesi.\
Na primer, malver bi mogao **ubaciti proizvoljni JS kod u otvorene stranice pretraživača**. Ili **automatski kliknuti** na neka dozvoljena ovlašćenja koja se traže od korisnika;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Evo nekoliko primera: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Pronađite više informacija o malveru koristeći applescripts [**ovde**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple skripte se mogu lako "**kompilirati**". Ove verzije se mogu lako "**dekompilirati**" pomoću `osadecompile`

Međutim, ove skripte se takođe mogu **izvesti kao "Samo za čitanje"** (putem opcije "Izvezi..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
i u ovom slučaju sadržaj se ne može dekompilirati čak ni sa `osadecompile`

Međutim, još uvek postoje neki alati koji se mogu koristiti za razumevanje ovakvih izvršnih datoteka, [**pročitajte ovo istraživanje za više informacija**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Alat [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) sa [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) će biti veoma koristan za razumevanje kako skripta funkcioniše.

{{#include ../../../../../banners/hacktricks-training.md}}
