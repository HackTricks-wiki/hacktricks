# Ontsnap uit KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Kontroleer fisiese toestel

| Component    | Aksie                                                               |
| ------------ | ------------------------------------------------------------------ |
| Kragknoppie  | Om die toestel af te skakel en weer aan te sit kan die beginskerm openbaar |
| Kragsnoer    | Kontroleer of die toestel herbegin wanneer die krag kortliks afgesny word |
| USB-poorte   | Koppel 'n fisiese sleutelbord vir meer snelkoppelinge              |
| Ethernet     | Netwerkskandering of sniffing kan verdere uitbuiting moontlik maak |

## Kontroleer vir moontlike aksies binne die GUI-toepassing

**Algemene dialoogvensters** is opsies soos **'n lêer stoor**, **'n lêer oopmaak**, 'n font kies, 'n kleur... Die meeste daarvan sal **'n volledige Explorer-funksionaliteit bied**. Dit beteken dat jy toegang tot Explorer-funksionaliteit sal hê as jy hierdie opsies kan bereik:

- Sluit/Sluit as
- Oopmaak/Oopmaak met
- Druk
- Eksporteer/Importeer
- Soek
- Skandeer

Jy moet kontroleer of jy kan:

- Wysig of nuwe lêers skep
- Simboliese skakels skep
- Toegang verkry tot beperkte gebiede
- Ander toepassings uitvoer

### Uitvoering van opdragte

Miskien kan jy, deur die `Open with` opsie te gebruik, 'n soort shell open/uitvoer.

#### Windows

Byvoorbeeld _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ vind meer binaries wat gebruik kan word om opdragte uit te voer (en om onverwagte aksies uit te voer) hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Meer hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Padbeperkings omseil

- **Omgewingveranderlikes**: Daar is baie omgewingveranderlikes wat na 'n pad wys
- **Ander protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Simboliese skakels**
- **Snelkoppelinge**: CTRL+N (open nuwe sessie), CTRL+R (Voer opdragte uit), CTRL+SHIFT+ESC (Taakbestuurder), Windows+E (open explorer), CTRL-B, CTRL-I (Favoriete), CTRL-H (Geskiedenis), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Verborge administratiewe kieslys: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell-URI's**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC-paaie**: Paaie om aan gedeelde vouers te koppel. Jy moet probeer koppel na die C$ van die plaaslike masjien ("\\\127.0.0.1\c$\Windows\System32")
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

### Beperkte Desktop-uitspringings (Citrix/RDS/VDI)

- **Dialoogvenster-pivotering**: Gebruik *Open/Save/Print-to-file* dialoogvensters as 'n ligte Explorer. Probeer `*.*` / `*.exe` in die lêernaamveld, regsklik op vouers vir **Open in nuwe venster**, en gebruik **Eienskappe → Open lêerligging** om navigasie uit te brei.
- **Skep uitvoeringspaaie vanuit dialoogvensters**: Skep 'n nuwe lêer en hernoem dit na `.CMD` of `.BAT`, of skep 'n kortpad wat na `%WINDIR%\System32` verwys (of 'n spesifieke binary soos `%WINDIR%\System32\cmd.exe`).
- **Shell-opstart-pivots**: As jy na `cmd.exe` kan blaai, probeer **sleep-en-loslaat** enige lêer daarop om 'n prompt te lanseer. As Taakbestuurder bereikbaar is (`CTRL+SHIFT+ESC`), gebruik **Voer nuwe taak uit**.
- **Taakskeduleerder-omseiling**: As interaktiewe shells geblokkeer is maar skedulering toegelaat, skep 'n taak om `cmd.exe` te laat loop (GUI `taskschd.msc` of `schtasks.exe`).
- **Swak toelatingslyste**: As uitvoering deur **lêernaam/uitbreiding** toegelaat word, hernoem jou payload na 'n toegelate naam. As dit toegelaat word deur **gids**, kopieer die payload na 'n toegelate programgids en voer dit daar uit.
- **Vind skryfbare staging-paaie**: Begin by `%TEMP%` en enumereer skryfbare vouers met Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Volgende stap**: As jy 'n shell kry, skuif na die Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Laai jou binaries af

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
- Toggle Keys – Hou NUMLOCK vir 5 sekondes ingedruk
- Filter Keys – Hou regte SHIFT vir 12 sekondes ingedruk
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Wys Desktop
- WINDOWS+E – Maak Windows Explorer oop
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Taakbestuurder
- CTRL+ALT+DEL – Splash screen on newer Windows versions
- F1 – Help F3 – Soek
- F6 – Adresbalk
- F11 – Wissel volle skerm in Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – Nuwe oortjie
- CTRL+N – Internet Explorer – Nuwe bladsy
- CTRL+O – Maak lêer oop
- CTRL+S – Stoor CTRL+N – Nuwe RDP / Citrix

### Swipe-beweginge

- Vee van die linkerkant na regs om alle oop Windows te sien, die KIOSK-app te minimaliseer en direk toegang tot die hele OS te kry;
- Vee van die regterkant na links om Action Center oop te maak, die KIOSK-app te minimaliseer en direk toegang tot die hele OS te kry;
- Vee van die boonste rand af om die titelbalk sigbaar te maak vir 'n app wat in volle skerm geopen is;
- Vee van onder af op om die taakbalk te toon in 'n volle skerm-app.

### Internet Explorer-truuks

#### 'Image Toolbar'

Dis 'n toolbar wat in die top-links van 'n beeld verskyn wanneer dit geklik word. Jy sal die opsies Save, Print, Mailto en Open "My Pictures" in Explorer hê. Die Kiosk moet Internet Explorer gebruik.

#### Shell-protokol

Tik hierdie URLs om 'n Explorer-uitsig te kry:

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

Kyk hierdie bladsy vir meer inligting: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Blaaier-truuks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Skep 'n algemene dialoog met JavaScript en kry toegang tot File Explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gebare en knoppies

- Vee op met vier (of vyf) vingers / Dubbel-tik die Home-knoppie: Om die multitask-uitsig te sien en van App te verander
- Vee een kant toe met vier of vyf vingers: Om na die volgende/vorige App te skakel
- Knyp die skerm met vyf vingers / Raak die Home-knoppie aan / Vee vinnig met 1 vinger vanaf die onderkant van die skerm op : Om by Home uit te kom
- Vee een vinger 1-2 duim vanaf die onderkant van die skerm (stadig): Die dok sal verskyn
- Vee vanaf die top van die skerm met 1 vinger af: Om jou kennisgewings te sien
- Vee af met 1 vinger die boonste-regterhoek van die skerm: Om iPad Pro se beheer-sentrum te sien
- Vee 1 vinger vanaf die linkerkant van die skerm 1-2 duim: Om die Today-view te sien
- Vee vinnig 1 vinger van die sentrum van die skerm na regs of links: Om na die volgende/vorige App te gaan
- Druk en hou die On/**Off**/Sleep-knoppie in die boonste-regterhoek van die **iPad +** skuif die Slide to **power off** skuifregterkant toe: Om af te skakel
- Druk die On/**Off**/Sleep-knoppie in die boonste-regterhoek van die **iPad en die Home-knoppie vir 'n paar sekondes**: Om 'n kragafskakeling te dwing
- Druk die On/**Off**/Sleep-knoppie in die boonste-regterhoek van die **iPad en die Home-knoppie vinnig**: Om 'n skermskoot te neem wat onder links op die skerm sal verskyn. Druk albei knoppies saam baie kortliks; as jy hulle 'n paar sekondes hou sal 'n harde kragafskakeling plaasvind.

### Kortpaaie

Jy behoort 'n iPad-toetsenbord of 'n USB-toetsenbordadapter te hê. Slegs kortpaaie wat kan help om uit die toepassing te ontsnap sal hier getoon word.

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

#### Stelsel-kortpaaie

| Shortcut | Action                                                                 |
| -------- | ---------------------------------------------------------------------- |
| F1       | Verlaag skermhelderheid                                                |
| F2       | Verhoog skermhelderheid                                                |
| F7       | Vorige liedjie                                                          |
| F8       | Play/pause                                                              |
| F9       | Skip liedjie                                                            |
| F10      | Demper                                                                  |
| F11      | Verlaag volume                                                          |
| F12      | Verhoog volume                                                          |
| ⌘ Space  | Vertoon 'n lys van beskikbare tale; om een te kies, druk weer die spasiebalk. |

#### iPad-navigasie

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gaan na Home                                            |
| ⌘⇧H (Command-Shift-H)                              | Gaan na Home                                            |
| ⌘ (Space)                                          | Maak Spotlight oop                                      |
| ⌘⇥ (Command-Tab)                                   | Lys die laaste tien gebruikte apps                      |
| ⌘\~                                                | Gaan na die laaste App                                  |
| ⌘⇧3 (Command-Shift-3)                              | Skermskoot (verskyn onder links om te stoor of te hanteer) |
| ⌘⇧4                                                | Skermskoot en maak dit in die redigeerder oop           |
| Press and hold ⌘                                   | Lys van kortpaaie beskikbaar vir die App                |
| ⌘⌥D (Command-Option/Alt-D)                         | Roep die dok op                                          |
| ^⌥H (Control-Option-H)                             | Home-knoppie                                             |
| ^⌥H H (Control-Option-H-H)                         | Wys multitask-balk                                       |
| ^⌥I (Control-Option-i)                             | Item-chooser                                             |
| Escape                                             | Terug-knoppie                                            |
| → (Right arrow)                                    | Volgende item                                             |
| ← (Left arrow)                                     | Vorige item                                               |
| ↑↓ (Up arrow, Down arrow)                          | Tegelykertyd die geselekteerde item tik                   |
| ⌥ ↓ (Option-Down arrow)                            | Scroll af                                                 |
| ⌥↑ (Option-Up arrow)                               | Scroll op                                                 |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Scroll links of regs                                       |
| ^⌥S (Control-Option-S)                             | Skakel VoiceOver-spraak aan of af                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Skakel na die vorige app                                  |
| ⌘⇥ (Command-Tab)                                   | Skakel terug na die oorspronklike app                     |
| ←+→, then Option + ← or Option+→                   | Navigeer deur die Dok                                     |

#### Safari-kortpaaie

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Open Location                                    |
| ⌘T                      | Maak 'n nuwe oortjie oop                         |
| ⌘W                      | Sluit die huidige oortjie                        |
| ⌘R                      | Herlaai die huidige oortjie                      |
| ⌘.                      | Stop die huidige oortjie se laai                 |
| ^⇥                      | Skakel na die volgende oortjie                   |
| ^⇧⇥ (Control-Shift-Tab) | Skakel na die vorige oortjie                     |
| ⌘L                      | Kies die teksinvoer/URL-veld om dit te wysig     |
| ⌘⇧T (Command-Shift-T)   | Maak laaste geslote oortjie oop (kan meerdere kere gebruik word) |
| ⌘\[                     | Gaan een bladsy terug in jou blaaigeskiedenis    |
| ⌘]                      | Gaan een bladsy vorentoe in jou blaaigeskiedenis |
| ⌘⇧R                     | Aktiveer Reader Mode                              |

#### Mail-kortpaaie

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Open Location                |
| ⌘T                         | Maak 'n nuwe oortjie oop     |
| ⌘W                         | Sluit die huidige oortjie    |
| ⌘R                         | Herlaai die huidige oortjie  |
| ⌘.                         | Stop die huidige oortjie se laai |
| ⌘⌥F (Command-Option/Alt-F) | Soek in jou posbus           |

## Verwysings

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
