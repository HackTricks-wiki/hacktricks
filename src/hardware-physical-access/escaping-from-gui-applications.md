# Izlazak iz KIOSK uređaja

{{#include ../banners/hacktricks-training.md}}

---

## Provera fizičkog uređaja

| Komponenta  | Radnja                                                           |
| ----------- | ---------------------------------------------------------------- |
| Dugme za napajanje | Isključivanje i ponovno uključivanje uređaja može prikazati početni ekran |
| Kabl za napajanje  | Proverite da li se uređaj ponovo pokreće kada se napajanje nakratko prekine |
| USB portovi | Povežite fizičku tastaturu sa dodatnim prečicama                      |
| Ethernet     | Skeniranje mreže ili sniffing mogu omogućiti dalju eksploataciju           |

## Provera mogućih radnji unutar GUI aplikacije

**Common Dialogs** su opcije za **čuvanje datoteke**, **otvaranje datoteke**, izbor fonta, boje... Većina njih će **ponuditi punu funkcionalnost Explorer-a**. To znači da ćete moći da pristupite funkcionalnostima Explorer-a ako možete da pristupite ovim opcijama:

- Zatvaranje/Zatvaranje kao
- Otvaranje/Otvori pomoću
- Štampanje
- Izvoz/Uvoz
- Pretraga
- Skeniranje

Trebalo bi da proverite da li možete da:

- Izmenite ili kreirate nove datoteke
- Kreirate simboličke linkove
- Dobijete pristup ograničenim oblastima
- Pokrenete druge aplikacije

### Command Execution

Možda **korišćenjem opcije `Open with`** možete da otvorite/pokrenete neku vrstu shell-a.

#### Windows

Na primer _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ ovde pronađite još binarnih datoteka koje se mogu koristiti za izvršavanje komandi (i obavljanje neočekivanih radnji): [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Više informacija ovde: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Zaobilaženje ograničenja putanja

- **Environment variables**: Postoji mnogo environment variables koje upućuju na određenu putanju
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (otvaranje nove sesije), CTRL+R (izvršavanje komandi), CTRL+SHIFT+ESC (Task Manager), Windows+E (otvaranje Explorer-a), CTRL-B, CTRL-I (Favorites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Skriveni Administrative meni: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Putanje za povezivanje sa deljenim folderima. Trebalo bi da pokušate da se povežete na C$ lokalne mašine ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: Koristite dijaloge *Open/Save/Print-to-file* kao Explorer-lite. Pokušajte sa `*.*` / `*.exe` u polju za ime datoteke, kliknite desnim tasterom miša na foldere za **Open in new window** i koristite **Properties → Open file location** da proširite navigaciju.<sup>[[1]](#references)</sup>
- **Create execution paths from dialogs**: Kreirajte novu datoteku i preimenujte je u `.CMD` ili `.BAT`, ili kreirajte shortcut koji pokazuje na `%WINDIR%\System32` (ili na određeni binary, kao što je `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Ako možete da pronađete `cmd.exe`, pokušajte da prevučete i otpustite (**drag-and-drop**) bilo koju datoteku na njega da biste pokrenuli prompt. Ako je Task Manager dostupan (`CTRL+SHIFT+ESC`), koristite **Run new task**.
- **Task Scheduler bypass**: Ako su interaktivni shell-ovi blokirani, ali je zakazivanje dozvoljeno, kreirajte task za pokretanje `cmd.exe` (GUI `taskschd.msc` ili `schtasks.exe`).
- **Weak allowlists**: Ako je izvršavanje dozvoljeno na osnovu **filename/extension**, preimenujte svoj payload u dozvoljeno ime. Ako je dozvoljeno na osnovu **directory**, kopirajte payload u dozvoljeni programski folder i tamo ga pokrenite.
- **Find writable staging paths**: Počnite sa `%TEMP%` i pronađite foldere u koje je moguće upisivati pomoću Sysinternals AccessChk-a.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Sledeći korak**: Ako dobijete shell, pređite na Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Preuzimanje binarnih datoteka

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Pristup filesystemu iz browsera

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
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Prikaži Desktop
- WINDOWS+E – Pokreni Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen na novijim verzijama Windowsa
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Uključi/isključi prikaz preko celog ekrana u Internet Exploreru
- CTRL+H – Istorija Internet Explorera
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Prevlačenja

- Prevucite sa leve strane nadesno da biste videli sve otvorene Windows prozore, minimizovali KIOSK aplikaciju i direktno pristupili celom OS-u;
- Prevucite sa desne strane nalevo da biste otvorili Action Center, minimizovali KIOSK aplikaciju i direktno pristupili celom OS-u;
- Prevucite od gornje ivice da bi naslovna traka postala vidljiva za aplikaciju otvorenu u režimu celog ekrana;
- Prevucite nagore od donje ivice da biste prikazali taskbar u aplikaciji preko celog ekrana.

### Trikovi za Internet Explorer

#### „Image Toolbar“

To je traka sa alatkama koja se pojavljuje u gornjem levom uglu slike kada kliknete na nju. Moći ćete da sačuvate, odštampate ili pošaljete sliku e-poštom, kao i da otvorite „My Pictures“ u Exploreru. Kiosk mora da koristi Internet Explorer.

#### Shell Protocol

Unesite ove URL-ove da biste dobili Explorer prikaz:

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

### Prikaz ekstenzija datoteka

Pogledajte ovu stranicu za više informacija: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Trikovi za browsere

Backup verzije iKat-a:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Kreirajte common dialog pomoću JavaScripta i pristupite file exploreru: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Izvor: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestovi i dugmad

- Prevucite nagore sa četiri (ili pet) prstiju / Dvaput dodirnite Home dugme: Da biste prikazali multitask prikaz i promenili aplikaciju
- Prevucite u jednom ili drugom smeru sa četiri ili pet prstiju: Da biste prešli na sledeću/prethodnu aplikaciju
- Skupite ekran sa pet prstiju / Dodirnite Home dugme / Brzo prevucite nagore jednim prstom od dna ekrana: Da biste pristupili početnom ekranu
- Prevucite jednim prstom od dna ekrana samo 1–2 inča naviše (polako): Dock će se pojaviti
- Prevucite jednim prstom nadole od vrha ekrana: Da biste videli obaveštenja
- Prevucite jednim prstom nadole od gornjeg desnog ugla ekrana: Da biste videli control centre iPad Pro uređaja
- Prevucite jednim prstom sa leve strane ekrana 1–2 inča nadesno: Da biste videli Today prikaz
- Brzo prevucite jednim prstom od sredine ekrana nadesno ili nalevo: Da biste prešli na sledeću/prethodnu aplikaciju
- Pritisnite i držite On/**Off**/Sleep dugme u gornjem desnom uglu uređaja **iPad +** Prevucite klizač **power off** skroz nadesno: Da biste isključili uređaj
- Pritisnite On/**Off**/Sleep dugme u gornjem desnom uglu uređaja **iPad i Home dugme nekoliko sekundi**: Da biste prinudno potpuno isključili uređaj
- Brzo pritisnite On/**Off**/Sleep dugme u gornjem desnom uglu uređaja **iPad i Home dugme**: Da biste napravili screenshot koji će se pojaviti u donjem levom uglu ekrana. Pritisnite oba dugmeta istovremeno veoma kratko, jer će se, ako ih držite nekoliko sekundi, izvršiti potpuno prinudno isključivanje.<sup>[[3]](#references)</sup>

### Prečice

Trebalo bi da imate iPad tastaturu ili USB adapter za tastaturu. Ovde će biti prikazane samo prečice koje mogu pomoći pri izlasku iz aplikacije.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Strelica ulevo   |
| →   | Strelica udesno  |
| ↑   | Strelica nagore     |
| ↓   | Strelica nadole     |

#### Sistemske prečice

Ove prečice služe za vizuelna podešavanja i podešavanja zvuka, u zavisnosti od korišćenja iPad uređaja.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Zatamni ekran                                                                    |
| F2       | Povećaj osvetljenost ekrana                                                                |
| F7       | Vrati prethodnu pesmu                                                                  |
| F8       | Reprodukuj/pauziraj                                                                     |
| F9       | Preskoči pesmu                                                                      |
| F10      | Isključi zvuk                                                                           |
| F11      | Smanji jačinu zvuka                                                                |
| F12      | Povećaj jačinu zvuka                                                                |
| ⌘ Space  | Prikaži listu dostupnih jezika; da biste izabrali jezik, ponovo dodirnite razmaknicu. |

#### iPad navigacija

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Idi na Home                                              |
| ⌘⇧H (Command-Shift-H)                              | Idi na Home                                              |
| ⌘ (Space)                                          | Otvori Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Prikaži poslednjih deset korišćenih aplikacija                                 |
| ⌘\~                                                | Idi na poslednju aplikaciju                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (pojavljuje se u donjem levom uglu radi čuvanja ili upravljanja) |
| ⌘⇧4                                                | Napravi screenshot i otvori ga u editoru                    |
| Pritisnite i držite ⌘                                   | Lista prečica dostupnih za aplikaciju                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Prikaži dock                                      |
| ^⌥H (Control-Option-H)                             | Home dugme                                             |
| ^⌥H H (Control-Option-H-H)                         | Prikaži multitask traku                                      |
| ^⌥I (Control-Option-i)                             | Birač stavki                                            |
| Escape                                             | Dugme za povratak                                             |
| → (Right arrow)                                    | Sledeća stavka                                               |
| ← (Left arrow)                                     | Prethodna stavka                                           |
| ↑↓ (Up arrow, Down arrow)                          | Istovremeno dodirnite izabranu stavku                        |
| ⌥ ↓ (Option-Down arrow)                            | Pomeranje nadole                                             |
| ⌥↑ (Option-Up arrow)                               | Pomeranje nagore                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Pomeranje ulevo ili udesno                                    |
| ^⌥S (Control-Option-S)                             | Uključi ili isključi VoiceOver govor                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Pređi na prethodnu aplikaciju                              |
| ⌘⇥ (Command-Tab)                                   | Vrati se na prvobitnu aplikaciju                         |
| ←+→, then Option + ← or Option+→                   | Kretanje kroz Dock                                   |

#### Safari prečice

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Otvori lokaciju                                    |
| ⌘T                      | Otvori novu karticu                                   |
| ⌘W                      | Zatvori trenutnu karticu                            |
| ⌘R                      | Osveži trenutnu karticu                          |
| ⌘.                      | Zaustavi učitavanje trenutne kartice                     |
| ^⇥                      | Pređi na sledeću karticu                           |
| ^⇧⇥ (Control-Shift-Tab) | Pređi na prethodnu karticu                         |
| ⌘L                      | Izaberi polje za unos teksta/URL da biste ga izmenili     |
| ⌘⇧T (Command-Shift-T)   | Otvori poslednju zatvorenu karticu (može se koristiti više puta) |
| ⌘\[                     | Vrati se jednu stranicu unazad u istoriji pregledanja      |
| ⌘]                      | Idi jednu stranicu unapred u istoriji pregledanja   |
| ⌘⇧R                     | Aktiviraj Reader Mode                             |

#### Prečice za Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Otvori lokaciju                |
| ⌘T                         | Otvori novu karticu               |
| ⌘W                         | Zatvori trenutnu karticu        |
| ⌘R                         | Osveži trenutnu karticu        |
| ⌘.                         | Zaustavi učitavanje trenutne kartice |
| ⌘⌥F (Command-Option/Alt-F) | Pretraži mailbox       |

## Reference

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
