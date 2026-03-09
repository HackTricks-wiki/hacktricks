# Bekstvo iz KIOSK-ova

{{#include ../banners/hacktricks-training.md}}

---

## Proverite fizički uređaj

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Isključivanje i ponovno uključivanje uređaja može otkriti početni ekran    |
| Power cable  | Proverite da li se uređaj restartuje kada se napajanje kratko prekine |
| USB ports    | Povežite fizičku tastaturu koja nudi više prečica                      |
| Ethernet     | Skeniranje ili presretanje mreže može omogućiti dalju eksploataciju           |

## Proverite moguće akcije unutar GUI aplikacije

**Common Dialogs** su one opcije kao što su **saving a file**, **opening a file**, odabir fonta, boje... Većina njih će **offer a full Explorer functionality**. To znači da ćete moći da pristupite Explorer funkcionalnostima ako možete da otvorite ove opcije:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Treba da proverite da li možete:

- Izmeniti ili kreirati nove fajlove
- Kreirati simboličke linkove
- Pristupiti ograničenim oblastima
- Pokrenuti druge aplikacije

### Izvršavanje komandi

Možda **koristeći `Open with`** opciju\*\* možete otvoriti/izvršiti neku vrstu shell-a.

#### Windows

Na primer _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ više binarnih fajlova koji se mogu iskoristiti za izvršavanje komandi (i izvođenje neočekivanih akcija) potražite ovde: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Više ovde: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Zaobilaženje ograničenja putanja

- **Environment variables**: Postoji mnogo environment variables koji ukazuju na određene putanje
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
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
- **Create execution paths from dialogs**: Kreirajte novi fajl i preimenujte ga u `.CMD` ili `.BAT`, ili napravite prečicu koja pokazuje na `%WINDIR%\System32` (ili na određeni binarni fajl kao `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Ako možete da pristupite `cmd.exe`, pokušajte da prevučete bilo koji fajl na njega da biste pokrenuli prompt. Ako je Task Manager dostupan (`CTRL+SHIFT+ESC`), koristite **Run new task**.
- **Task Scheduler bypass**: Ako su interaktivni shell-ovi blokirani ali je dozvoljeno planiranje, napravite task koji će pokrenuti `cmd.exe` (GUI `taskschd.msc` ili `schtasks.exe`).
- **Weak allowlists**: Ako je izvršavanje dozvoljeno po **filename/extension**, preimenujte payload u dozvoljeno ime. Ako je dozvoljeno po **directory**, kopirajte payload u dozvoljen program folder i pokrenite ga odatle.
- **Find writable staging paths**: Počnite sa `%TEMP%` i enumerišite upisive foldere koristeći Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Next step**: If you gain a shell, pivot to the Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Preuzimanje binarnih fajlova

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Pristupanje fajl sistemu iz pregledača

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
- Toggle Keys – Hold NUMLOCK for 5 seconds
- Filter Keys – Hold right SHIFT for 12 seconds
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Show Desktop
- WINDOWS+E – Launch Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen on newer Windows versions
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Toggle full screen within Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Prevlačenja (Swipes)

- Prevucite sa leve strane ka desnoj da vidite sve otvorene Windows, minimizujući KIOSK aplikaciju i direktno pristupajući celom OS-u;
- Prevucite sa desne strane ka levoj da otvorite Action Center, minimizujući KIOSK aplikaciju i direktno pristupajući celom OS-u;
- Prevucite odozgo da bi naslovna traka bila vidljiva za aplikaciju otvorenu u full screen modu;
- Prevucite nagore sa dna da prikažete taskbar u full screen aplikaciji.

### Internet Explorer trikovi

#### 'Image Toolbar'

To je alatna traka koja se pojavljuje u gornjem levom uglu slike kada se klikne. Moći ćete da Save, Print, Mailto, Open "My Pictures" u Explorer-u. Kiosk mora koristiti Internet Explorer.

#### Shell Protocol

Unesite ove URL-ove da biste dobili prikaz Explorer-a:

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

Kreirajte standardni dialog koristeći JavaScript i pristupite Explorer-u: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestovi i dugmad

- Prevucite nagore sa četiri (ili pet) prsta / Dvaput dodirnite Home dugme: Prikaz multitask pregleda i promena aplikacije
- Prevucite levo ili desno sa četiri ili pet prstiju: Za prelazak na sledeću/prethodnu aplikaciju
- Stisnite ekran sa pet prstiju / Dodirnite Home dugme / Prevucite nagore sa 1 prsta od dna ekrana brzim pokretom nagore: Za povratak na Home
- Prevucite jednim prstom od dna ekrana samo 1–2 inča (sporo): Dock će se pojaviti
- Prevucite dole sa vrha displeja jednim prstom: Prikazuje obaveštenja
- Prevucite dole sa gornje-desne strane ekrana jednim prstom: Prikazuje control centre na iPad Pro
- Prevucite jednim prstom sa leve strane ekrana 1–2 inča: Prikazuje Today view
- Brzo prevucite jednim prstom iz centra ekrana udesno ili ulevo: Promena na sledeću/prethodnu aplikaciju
- Pritisnite i držite On/**Off**/Sleep dugme u gornjem desnom uglu **iPad-a +** pomerite Slide to **power off** klizač skroz udesno: Isključivanje uređaja
- Pritisnite On/**Off**/Sleep dugme u gornjem desnom uglu **iPad-a i Home dugme nekoliko sekundi**: Forsirano hard power off
- Pritisnite On/**Off**/Sleep dugme u gornjem desnom uglu **iPad-a i Home dugme brzo**: Pravljenje screenshot-a koji će se pojaviti u donjem levom uglu ekrana. Pritisnite oba dugmeta istovremeno vrlo kratko; ako ih držite nekoliko sekundi biće izvršen hard power off.

### Prečice

Trebalo bi da imate iPad tastaturu ili USB adapter za tastaturu. Prikažemo samo prečice koje mogu pomoći za bekstvo iz aplikacije.

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

Ove prečice su za vizuelna i zvučna podešavanja, u zavisnosti od upotrebe iPada.

| Prečica | Radnja                                                                         |
| ------- | ------------------------------------------------------------------------------ |
| F1      | Smanji osvetljenje ekrana                                                      |
| F2      | Povećaj osvetljenje ekrana                                                     |
| F7      | Prethodna pesma                                                                 |
| F8      | Play/pause                                                                      |
| F9      | Preskoči pesmu                                                                  |
| F10     | Isključi zvuk                                                                   |
| F11     | Smanji zvuk                                                                      |
| F12     | Povećaj zvuk                                                                     |
| ⌘ Space | Prikaži listu dostupnih jezika; da izaberete jedan, ponovo pritisnite space bar. |

#### Navigacija na iPadu

| Prečica                                           | Radnja                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Idi na početni ekran                                     |
| ⌘⇧H (Command-Shift-H)                              | Idi na početni ekran                                     |
| ⌘ (Space)                                          | Otvori Spotlight                                         |
| ⌘⇥ (Command-Tab)                                   | Prikaži poslednjih deset korišćenih aplikacija           |
| ⌘\~                                                | Idi na poslednju aplikaciju                              |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (pojavljuje se u donjem levom uglu za čuvanje/akciju) |
| ⌘⇧4                                                | Screenshot i otvaranje u editoru                         |
| Press and hold ⌘                                   | Lista prečica dostupnih za aplikaciju                    |
| ⌘⌥D (Command-Option/Alt-D)                         | Prikazuje dock                                           |
| ^⌥H (Control-Option-H)                             | Home dugme                                               |
| ^⌥H H (Control-Option-H-H)                         | Prikaži multitask traku                                  |
| ^⌥I (Control-Option-i)                             | Item chooser                                             |
| Escape                                             | Back button                                              |
| → (Right arrow)                                    | Sledeći item                                             |
| ← (Left arrow)                                     | Prethodni item                                           |
| ↑↓ (Up arrow, Down arrow)                          | Simultano potvrdi izabrani item                          |
| ⌥ ↓ (Option-Down arrow)                            | Skroluj nadole                                           |
| ⌥↑ (Option-Up arrow)                               | Skroluj nagore                                           |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Skroluj levo ili desno                                   |
| ^⌥S (Control-Option-S)                             | Uključi/isključi VoiceOver govor                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Prebaci na prethodnu aplikaciju                          |
| ⌘⇥ (Command-Tab)                                   | Vratite se na originalnu aplikaciju                      |
| ←+→, then Option + ← or Option+→                   | Navigacija kroz Dock                                     |

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
| ⌘L                      | Selektuj tekst/URL polje za izmenu               |
| ⌘⇧T (Command-Shift-T)   | Otvori poslednji zatvoreni tab (može se koristiti više puta) |
| ⌘\[                     | Vraća se jednu stranu unazad u istoriji          |
| ⌘]                      | Ide napred jednu stranu u istoriji               |
| ⌘⇧R                     | Aktivira Reader Mode                              |

#### Mail prečice

| Prečica                   | Radnja                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Otvori lokaciju              |
| ⌘T                         | Otvori novi tab              |
| ⌘W                         | Zatvori trenutni tab         |
| ⌘R                         | Osveži trenutni tab          |
| ⌘.                         | Zaustavi učitavanje taba     |
| ⌘⌥F (Command-Option/Alt-F) | Pretraži svoj poštanski sandučić |

## Reference

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
