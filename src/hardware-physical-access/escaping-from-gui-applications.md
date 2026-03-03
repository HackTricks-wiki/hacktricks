# Escaping from KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Provera fizičkog uređaja

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Isključivanje i ponovno uključivanje uređaja može otkriti početni ekran    |
| Power cable  | Proverite da li se uređaj restartuje kada se napajanje na kratko prekine |
| USB ports    | Povežite fizičku tastaturu sa više prečica                      |
| Ethernet     | Network scan ili sniffing mogu omogućiti dalju eksploataciju           |

## Provera mogućih akcija unutar GUI aplikacije

**Common Dialogs** su opcije kao što su **saving a file**, **opening a file**, izbor fonta, boje... Većina njih će **offer a full Explorer functionality**. To znači da ćete moći da pristupite Explorer funkcionalnostima ako možete da pristupite ovim opcijama:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Treba da proverite da li možete:

- Modifikovati ili kreirati nove fajlove
- Kreirati simboličke linkove
- Pristupiti ograničenim oblastima
- Pokrenuti druge aplikacije

### Izvršavanje komandi

Možda **using a `Open with`** option\*\* možete otvoriti/izvršiti neku vrstu shell-a.

#### Windows

Na primer _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pronađite više binarnih fajlova koji se mogu koristiti za izvršavanje komandi (i izvođenje neočekivanih radnji) ovde: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Više ovde: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Zaobilaženje ograničenja putanje

- **Environment variables**: Postoji mnogo environment variables koji ukazuju na određene putanje
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (otvori novu sesiju), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (otvori Explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Skriveni Administrativni meni: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Putanje za povezivanje na deljene foldere. Trebalo bi da pokušate da se povežete na C$ lokalne mašine ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Koristite *Open/Save/Print-to-file* dijaloge kao Explorer-lite. Probajte `*.*` / `*.exe` u polju za ime fajla, desni klik na foldere za **Open in new window**, i koristite **Properties → Open file location** da proširite navigaciju.
- **Create execution paths from dialogs**: Kreirajte novi fajl i preimenujte ga u `.CMD` ili `.BAT`, ili kreirajte shortcut koji pokazuje na `%WINDIR%\System32` (ili na određeni binary kao `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Ako možete da pretražujete do `cmd.exe`, pokušajte da **drag-and-drop** bilo koji fajl na njega da pokrenete prompt. Ako je Task Manager dostupan (`CTRL+SHIFT+ESC`), koristite **Run new task**.
- **Task Scheduler bypass**: Ako su interaktivni shell-ovi blokirani ali je zakazivanje dozvoljeno, kreirajte task koji pokreće `cmd.exe` (GUI `taskschd.msc` ili `schtasks.exe`).
- **Weak allowlists**: Ako je izvršavanje dozvoljeno po **filename/extension**, preimenujte svoj payload u dozvoljeno ime. Ako je dozvoljeno po **directory**, kopirajte payload u dozvoljeni programski folder i pokrenite ga odatle.
- **Find writable staging paths**: Počnite sa `%TEMP%` i enumerate writeable foldere pomoću Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Sledeći korak**: Ako dobijete shell, pređite na Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Preuzmite binarne fajlove

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Pristup fajl sistemu iz pregledača

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Prečice

- Sticky Keys – Pritisnite SHIFT 5 puta
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Držite NUMLOCK 5 sekundi
- Filter Keys – Držite desni SHIFT 12 sekundi
- WINDOWS+F1 – Windows pretraga
- WINDOWS+D – Prikaži radnu površinu
- WINDOWS+E – Pokreni Windows Explorer
- WINDOWS+R – Pokreni
- WINDOWS+U – Centar za olakšan pristup
- WINDOWS+F – Pretraga
- SHIFT+F10 – Kontekstni meni
- CTRL+SHIFT+ESC – Upravljač zadacima
- CTRL+ALT+DEL – Ekran sa opcijama na novijim verzijama Windows-a
- F1 – Pomoć  F3 – Pretraga
- F6 – Traka adrese
- F11 – Uključi/isključi prikaz preko celog ekrana u Internet Explorer-u
- CTRL+H – Istorija Internet Explorera
- CTRL+T – Internet Explorer – Novi tab
- CTRL+N – Internet Explorer – Nova stranica
- CTRL+O – Otvori fajl
- CTRL+S – Sačuvaj CTRL+N – Novi RDP / Citrix

### Prevlačenja

- Prevucite prst sa leve strane udesno da vidite sve otvorene Windows prozore, minimizujući KIOSK aplikaciju i direktno pristupajući OS-u;
- Prevucite prst sa desne strane ulevo da otvorite Action Center, minimizujući KIOSK aplikaciju i direktno pristupajući OS-u;
- Prevucite prst odozgo da bi naslovna traka postala vidljiva za aplikaciju otvorenu u punom ekranu;
- Prevucite prst odozdo nagore da bi se prikazala taskbar u aplikaciji punog ekrana.

### Trikovi za Internet Explorer

#### 'Image Toolbar'

To je alatna traka koja se pojavljuje u gornjem levom uglu slike kada se klikne na nju. Moći ćete da Sačuvate, Štampate, Mailto, Otvorite "My Pictures" u Explorer-u. Kiosk mora da koristi Internet Explorer.

#### Shell Protocol

Unesite ove URL-ove da biste dobili prikaz Explorera:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Prikaz ekstenzija fajlova

Pogledajte ovu stranicu za više informacija: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Trikovi za pregledače

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Kreirajte standardni dijalog koristeći JavaScript i pristupite File Explorer-u: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Geste i dugmad

- Prevucite nagore sa četiri (ili pet) prsta / Duplo pritisnite Home dugme: Za prikaz multitask prikaza i promenu aplikacije
- Prevucite levo ili desno sa četiri ili pet prstiju: Za prelazak na sledeću/prethodnu aplikaciju
- Stisnite ekran sa pet prstiju / Dodirnite Home dugme / Prevucite nagore sa 1 prstom od dna ekrana brzo nagore: Za pristup početnom ekranu
- Prevucite jednim prstom od dna ekrana 1-2 inča (polako): Dock će se pojaviti
- Prevucite nadole sa vrha ekrana jednim prstom: Da vidite notifikacije
- Prevucite nadole jednim prstom u gornjem desnom uglu ekrana: Da vidite kontrolni centar iPad Pro-a
- Prevucite jednim prstom sa leve strane ekrana 1-2 inča: Da vidite Today view
- Brzo prevucite jednim prstom iz centra ekrana udesno ili ulevo: Da promenite na sledeću/prethodnu aplikaciju
- Pritisnite i držite dugme On/**Off**/Sleep u gornjem desnom uglu **iPad +** Pomaknite Slide do **power off** klizača skroz udesno: Za isključivanje
- Pritisnite dugme On/**Off**/Sleep u gornjem desnom uglu **iPad and the Home button for a few second**: Za primorano hard isključivanje
- Pritisnite brzo dugme On/**Off**/Sleep u gornjem desnom uglu **iPad and the Home button quickly**: Da napravite screenshot koji će se pojaviti u donjem levom uglu ekrana. Pritisnite oba dugmeta istovremeno vrlo kratko; ako ih držite nekoliko sekundi, izvršiće se prisilno hard isključivanje.

### Prečice

Trebalo bi da imate iPad tastaturu ili USB adapter za tastaturu. Prikazane su samo prečice koje mogu pomoći pri bekstvu iz aplikacije.

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### Sistemske prečice

| Prečica  | Radnja                                                                 |
| -------- | ---------------------------------------------------------------------- |
| F1       | Zatamni ekran                                                          |
| F2       | Pojačaj osvetljenje ekrana                                             |
| F7       | Prethodna pesma                                                        |
| F8       | Reprodukuj/pauziraj                                                    |
| F9       | Preskoči pesmu                                                         |
| F10      | Isključi zvuk                                                          |
| F11      | Smanji jačinu zvuka                                                    |
| F12      | Povećaj jačinu zvuka                                                   |
| ⌘ Space  | Prikaži listu dostupnih jezika; za izbor dodirnite ponovo razmaknicu.  |

#### Navigacija na iPadu

| Prečica                                           | Radnja                                                          |
| -------------------------------------------------- | --------------------------------------------------------------- |
| ⌘H                                                 | Idi na Početni ekran                                            |
| ⌘⇧H (Command-Shift-H)                              | Idi na Početni ekran                                            |
| ⌘ (Space)                                          | Otvori Spotlight                                                |
| ⌘⇥ (Command-Tab)                                   | Prikaz poslednjih deset korišćenih aplikacija                   |
| ⌘\~                                                | Pređi na poslednju aplikaciju                                   |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (pojaviće se u donjem levom uglu da sačuvate ili postupite dalje) |
| ⌘⇧4                                                | Screenshot i otvori ga u editoru                                |
| Press and hold ⌘                                   | Lista prečica dostupnih za aplikaciju                           |
| ⌘⌥D (Command-Option/Alt-D)                         | Prikazuje dock                                                  |
| ^⌥H (Control-Option-H)                             | Dugme Početak                                                   |
| ^⌥H H (Control-Option-H-H)                         | Prikaži multitask traku                                          |
| ^⌥I (Control-Option-i)                             | Biranje stavke                                                   |
| Escape                                             | Dugme Nazad                                                      |
| → (Right arrow)                                    | Sledeći element                                                  |
| ← (Left arrow)                                     | Prethodni element                                                |
| ↑↓ (Up arrow, Down arrow)                          | Istovremeno izaberite selektovani element                        |
| ⌥ ↓ (Option-Down arrow)                            | Skroluj nadole                                                   |
| ⌥↑ (Option-Up arrow)                               | Skroluj nagore                                                   |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Skroluj levo ili desno                                           |
| ^⌥S (Control-Option-S)                             | Uključi/isključi VoiceOver govor                                 |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Prebaci na prethodnu aplikaciju                                  |
| ⌘⇥ (Command-Tab)                                   | Vrati se u originalnu aplikaciju                                 |
| ←+→, then Option + ← or Option+→                   | Navigacija kroz Dock                                              |

#### Safari prečice

| Prečica                | Radnja                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Otvori lokaciju                                  |
| ⌘T                      | Otvori novi tab                                  |
| ⌘W                      | Zatvori trenutni tab                             |
| ⌘R                      | Osveži trenutni tab                              |
| ⌘.                      | Zaustavi učitavanje trenutnog taba               |
| ^⇥                      | Prebaci na sledeći tab                           |
| ^⇧⇥ (Control-Shift-Tab) | Prebaci na prethodni tab                         |
| ⌘L                      | Selektuj polje za unos/URL da ga izmenite       |
| ⌘⇧T (Command-Shift-T)   | Otvori poslednji zatvoreni tab (može se koristiti više puta) |
| ⌘\[                     | Vraća se na jednu stranicu unazad                |
| ⌘]                      | Ide jedan korak napred u istoriji pretrage       |
| ⌘⇧R                     | Aktivira Reader režim                            |

#### Mail prečice

| Prečica                   | Radnja                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Otvori lokaciju              |
| ⌘T                         | Otvori novi tab              |
| ⌘W                         | Zatvori trenutni tab         |
| ⌘R                         | Osveži trenutni tab          |
| ⌘.                         | Zaustavi učitavanje taba     |
| ⌘⌥F (Command-Option/Alt-F) | Pretraži sanduče             |

## Reference

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
