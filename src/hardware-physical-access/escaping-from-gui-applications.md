# Ontsnap uit KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Kontroleer fisiese toestel

| Komponent    | Aksie                                                               |
| ------------ | ------------------------------------------------------------------- |
| Kragknop     | Om die toestel af en weer aan te skakel kan die beginskerm blootstel |
| Kragsnoer    | Kontroleer of die toestel herbegin wanneer die krag kortliks afgesny word |
| USB-poorte   | Koppel 'n fisiese sleutelbord vir meer sneltoetse                   |
| Ethernet     | Netwerkskandering of sniffing kan verdere uitbuiting moontlik maak  |

## Kontroleer moontlike aksies binne die GUI-toepassing

**Common Dialogs** is die opsies om 'n lêer te stoor, 'n lêer te open, 'n font te kies, 'n kleur... Die meeste sal **volle Explorer-funksionaliteit** bied. Dit beteken dat jy toegang tot Explorer-funksies sal hê as jy toegang tot hierdie opsies kry:

- Sluit/Sluit as
- Open/Open with
- Druk af
- Eksporteer/Importeer
- Soek
- Skandeer

Jy moet kontroleer of jy kan:

- Wysig of nuwe lêers skep
- Simboliese skakels skep
- Toegang tot beperkte areas verkry
- Ander apps uitvoer

### Command Execution

Miskien **using a `Open with`** option\*\* kan jy 'n soort shell open/uitvoer.

#### Windows

Byvoorbeeld _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ vind meer binaries wat gebruik kan word om opdragte uit te voer (en onvoorsiene aksies te verrig) hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ More here: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Padbeperkings omseil

- **Omgewingsveranderlikes**: Daar is baie omgewingsveranderlikes wat na 'n pad wys
- **Ander protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Simboliese skakels**
- **Kortpaaie**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Verborge administratiewe kieslys: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Paaie om aan gedeelde vouers te koppel. Jy moet probeer koppel aan die C$ van die plaaslike masjien ("\\\127.0.0.1\c$\Windows\System32")
- **Meer UNC-paaie:**

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

### Beperkte Desktop-ontsnappings (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Gebruik *Open/Save/Print-to-file* dialoë as Explorer-lite. Probeer `*.*` / `*.exe` in die lêernaamveld, klik regs op vouers vir **Open in new window**, en gebruik **Properties → Open file location** om navigasie uit te brei.
- **Create execution paths from dialogs**: Skep 'n nuwe lêer en hernoem dit na `.CMD` of `.BAT`, of skep 'n snelkoppeling wat na `%WINDIR%\System32` wys (of 'n spesifieke binary soos `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: As jy na `cmd.exe` kan blaai, probeer **drag-and-drop** enige lêer daarop om 'n prompt te begin. As Taakbestuurder bereikbaar is (`CTRL+SHIFT+ESC`), gebruik **Run new task**.
- **Task Scheduler bypass**: As interaktiewe shells geblokkeer is maar skedulering toegelaat word, skep 'n taak om `cmd.exe` te laat loop (GUI `taskschd.msc` of `schtasks.exe`).
- **Swak allowlists**: As uitvoering toegelaat word deur **filename/extension**, hernoem jou payload na 'n toegelate naam. As dit deur **directory** toegelaat word, kopieer die payload na 'n toegelate program-lêergids en voer dit daar uit.
- **Vind skryfbare staging-paaie**: Begin by `%TEMP%` en enumereer skryfbare vouers met Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Volgende stap**: As jy 'n shell kry, skakel oor na die Windows LPE-checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Laai jou Binaries af

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Toegang tot die lêerstelsel vanaf die blaaier

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Kortpaaie

- Sticky Keys – Druk SHIFT 5 keer
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Hou NUMLOCK 5 sekondes gedruk
- Filter Keys – Hou regter SHIFT 12 sekondes gedruk
- WINDOWS+F1 – Windows-soektog
- WINDOWS+D – Wys lessenaar
- WINDOWS+E – Start Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Sentrum vir Toeganklikheid
- WINDOWS+F – Soek
- SHIFT+F10 – Konteksmenu
- CTRL+SHIFT+ESC – Taakbestuurder
- CTRL+ALT+DEL – Splash-skerm op nuwer Windows-weergawes
- F1 – Hulp  F3 – Soek
- F6 – Adresbalk
- F11 – Skakel volle skerm in Internet Explorer
- CTRL+H – Internet Explorer-geskiedenis
- CTRL+T – Internet Explorer – Nuwe oortjie
- CTRL+N – Internet Explorer – Nuwe bladsy
- CTRL+O – Open lêer
- CTRL+S – Stoor  CTRL+N – Nuwe RDP / Citrix

### Veegbeweginge

- Veeg van die linkerkant na regs om al die oop Windows te sien, waarmee die KIOSK-app geminimeer word en jy direk toegang tot die hele OS kry;
- Veeg van die regterkant na links om Action Center te open, waarmee die KIOSK-app geminimeer word en jy direk toegang tot die hele OS kry;
- Veeg in vanaf die boonste rand om die titelbalk sigbaar te maak vir 'n app wat in volle skermmodus oop is;
- Veeg op vanaf die onderkant om die taakbalk te wys in 'n volle skerm-app.

### Internet Explorer-wenke

#### 'Image Toolbar'

Dit is 'n werkbalk wat links bo op 'n beeld verskyn wanneer dit geklik word. Jy sal kan Stoor, Druk, Mailto en "My Pictures" in Explorer oopmaak. Die Kiosk moet Internet Explorer gebruik.

#### Shell-protokol

Tik hierdie URL's om 'n Explorer-kyk te kry:

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

### Wys lêeruitbreidings

Kyk na hierdie bladsy vir meer inligting: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Blaaierwenke

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Skep 'n algemene dialoog met JavaScript en kry toegang tot lêerverkenner: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gebare en knoppies

- Veeg op met vier (of vyf) vingers / Dubbel-tik die Home-knoppie: Om die multitask-uitsig te sien en 'n app te verander
- Veeg een kant toe met vier of vyf vingers: Om na die volgende/vorige app te skakel
- Knyp die skerm met vyf vingers / Tik die Home-knoppie / Veeg vinnig op met 1 vinger vanaf die onderkant van die skerm: Om by Home uit te kom
- Veeg een vinger vanaf die onderkant van die skerm net 1–2 duim (stadig): Die dok sal verskyn
- Veeg af vanaf die bokant van die vertoning met 1 vinger: Om jou kennisgewings te sien
- Veeg af met 1 vinger in die boonste-regterhoek van die skerm: Om iPad Pro se beheersentrum te sien
- Veeg 1 vinger vanaf die linkerkant van die skerm 1–2 duim: Om Today view te sien
- Veeg vinnig 1 vinger van die middel van die skerm na regs of links: Om na die volgende/vorige app te skakel
- Druk en hou die On/**Off**/Sleep-knoppie aan die boonste-regterhoek van die **iPad** en skuif die Slide to **power off**-skuifknop heeltemal na regs: Om uit te skakel
- Druk en hou die On/**Off**/Sleep-knoppie aan die boonste-regterhoek van die **iPad** en die Home-knoppie vir 'n paar sekondes: Om 'n geforseerde harde afskakeling te doen
- Druk die On/**Off**/Sleep-knoppie aan die boonste-regterhoek van die **iPad** en die Home-knoppie vinnig: Om 'n skermfoto te neem wat onder links op die vertoning sal verskyn. Druk albei knoppies gelyktydig baie kortliks; as jy hulle 'n paar sekondes hou, sal 'n harde afskakeling uitgevoer word.

### Kortpaaie

Jy behoort 'n iPad-toetsenbord of 'n USB-toetsenbordadapter te hê. Slegs kortpaaie wat kan help om uit die toepassing te ontsnap, word hier getoon.

| Sleutel | Naam         |
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

#### Stelsel-kortpaaie

| Kortpad | Aksie                                                                 |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Skerm verdof                                                                  |
| F2       | Skerm verhelder                                                                |
| F7       | Vorige liedjie                                                                 |
| F8       | Speel/pauze                                                                     |
| F9       | Slaan liedjie oor                                                               |
| F10      | Demp                                                                            |
| F11      | Verlaag volume                                                                  |
| F12      | Verhoog volume                                                                  |
| ⌘ Space  | Vertoon 'n lys van beskikbare tale; om een te kies, tik weer die spasiebalk. |

#### iPad-navigasie

| Kortpad                                           | Aksie                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gaan na Home                                            |
| ⌘⇧H (Command-Shift-H)                              | Gaan na Home                                            |
| ⌘ (Space)                                          | Maak Spotlight oop                                      |
| ⌘⇥ (Command-Tab)                                   | Lys van die laaste tien gebruikte apps                 |
| ⌘\~                                                | Gaan na die laaste app                                  |
| ⌘⇧3 (Command-Shift-3)                              | Skermfoto (verskyn onder links om te stoor of op te tree) |
| ⌘⇧4                                                | Skermfoto en maak dit in die editor oop                 |
| Press and hold ⌘                                   | Lys van kortpaaie beskikbaar vir die App               |
| ⌘⌥D (Command-Option/Alt-D)                         | Roep die dok op                                         |
| ^⌥H (Control-Option-H)                             | Home-knoppie                                            |
| ^⌥H H (Control-Option-H-H)                         | Wys multitask-balk                                      |
| ^⌥I (Control-Option-i)                             | Item-kieër                                              |
| Escape                                             | Terug-knoppie                                           |
| → (Right arrow)                                    | Volgende item                                           |
| ← (Left arrow)                                     | Vorige item                                             |
| ↑↓ (Up arrow, Down arrow)                          | Tik gelyktydig die geselekteerde item                   |
| ⌥ ↓ (Option-Down arrow)                            | Blaai af                                                |
| ⌥↑ (Option-Up arrow)                               | Blaai op                                                |
| ⌥← of ⌥→ (Option-Left arrow or Option-Right arrow) | Blaai links of regs                                      |
| ^⌥S (Control-Option-S)                             | Skakel VoiceOver-spraak aan of af                       |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Skakel na die vorige app                                 |
| ⌘⇥ (Command-Tab)                                   | Skakel terug na die oorspronklike app                    |
| ←+→, then Option + ← or Option+→                   | Navigeer deur die dok                                    |

#### Safari-kortpaaie

| Kortpad                | Aksie                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Open Location                                    |
| ⌘T                      | Maak 'n nuwe oortjie oop                         |
| ⌘W                      | Maak die huidige oortjie toe                     |
| ⌘R                      | Herlaai die huidige oortjie                      |
| ⌘.                      | Stop die laai van die huidige oortjie            |
| ^⇥                      | Skakel na die volgende oortjie                   |
| ^⇧⇥ (Control-Shift-Tab) | Gaan na die vorige oortjie                       |
| ⌘L                      | Selekteer die teksinvoer/URL-veld om dit te wysig |
| ⌘⇧T (Command-Shift-T)   | Maak die laaste geslote oortjie oop (kan meermaals gebruik word) |
| ⌘\[                     | Gaan een blad terug in jou blaai-geskiedenis     |
| ⌘]                      | Gaan een blad vorentoe in jou blaai-geskiedenis  |
| ⌘⇧R                     | Aktiveer Reader Mode                             |

#### Mail-kortpaaie

| Kortpad                   | Aksie                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Open Location                |
| ⌘T                         | Maak 'n nuwe oortjie oop     |
| ⌘W                         | Maak die huidige oortjie toe |
| ⌘R                         | Herlaai die huidige oortjie  |
| ⌘.                         | Stop die laai van die huidige oortjie |
| ⌘⌥F (Command-Option/Alt-F) | Soek in jou posbus           |

## Verwysings

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
