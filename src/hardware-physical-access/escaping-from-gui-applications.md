# Ontsnap uit KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Kontroleer fisiese toestel

| Komponent    | Aksie                                                             |
| ------------ | ------------------------------------------------------------------ |
| Aan/af-knoppie | Deur die toestel af en weer aan te skakel, kan die beginskerm sigbaar word |
| Kragkabel  | Kontroleer of die toestel herlaai wanneer die krag kortliks afgeskakel word |
| USB-poorte    | Koppel ’n fisiese sleutelbord met meer kortpaaie                      |
| Ethernet     | ’n Netwerkskandering of sniffing kan verdere exploitation moontlik maak           |

## Kontroleer moontlike aksies binne die GUI application

**Algemene dialoogvensters** is daardie opsies om **’n file te stoor**, **’n file oop te maak**, ’n font, ’n kleur te kies... Die meeste daarvan sal **volledige Explorer-funksionaliteit bied**. Dit beteken dat jy toegang tot Explorer-funksionaliteit sal hê as jy toegang tot hierdie opsies kan verkry:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Jy moet kontroleer of jy:

- Nuwe files kan wysig of skep
- symbolic links kan skep
- Toegang tot beperkte areas kan verkry
- Ander apps kan uitvoer

### Command Execution

Miskien kan jy **’n `Open with`**-opsie gebruik\*\* om ’n soort shell oop te maak/uit te voer.

#### Windows

Byvoorbeeld _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ vind meer binaries wat gebruik kan word om commands uit te voer (en onverwagte aksies uit te voer) hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Meer hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassing path restrictions

- **Environment variables**: Daar is baie environment variables wat na ’n path wys
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open nuwe sessie), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open Explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Versteekte Administratiewe menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Paths om aan shared folders te koppel. Jy moet probeer om aan die plaaslike masjien se C$ te koppel ("\\\127.0.0.1\c$\Windows\System32")
- **Meer UNC paths:**

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

- **Dialog-box pivoting**: Gebruik *Open/Save/Print-to-file*-dialoogvensters as Explorer-lite. Probeer `*.*` / `*.exe` in die filename-veld, regsklik op folders vir **Open in new window**, en gebruik **Properties → Open file location** om navigasie uit te brei.<sup>[[1]](#references)</sup>
- **Skep uitvoeringspaths vanuit dialoogvensters**: Skep ’n nuwe file en hernoem dit na `.CMD` of `.BAT`, of skep ’n shortcut wat na `%WINDIR%\System32` (of ’n spesifieke binary soos `%WINDIR%\System32\cmd.exe`) wys.
- **Shell launch pivots**: As jy na `cmd.exe` kan navigeer, probeer om enige file daarop te **sleep-en-los** om ’n prompt te begin. As Task Manager bereikbaar is (`CTRL+SHIFT+ESC`), gebruik **Run new task**.
- **Task Scheduler bypass**: As interaktiewe shells geblokkeer word, maar scheduling toegelaat word, skep ’n task om `cmd.exe` uit te voer (GUI `taskschd.msc` of `schtasks.exe`).
- **Weak allowlists**: As uitvoering volgens **filename/extension** toegelaat word, hernoem jou payload na ’n toegelate naam. As dit volgens **directory** toegelaat word, kopieer die payload na ’n toegelate programfolder en voer dit daar uit.
- **Vind skryfbare staging paths**: Begin met `%TEMP%` en enumerateer skryfbare folders met Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Volgende stap**: As jy 'n shell verkry, gaan voort na die Windows LPE-kontrolelys:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Laai jou binaries af

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registerredigeerder: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Toegang tot die lêerstelsel vanaf die browser

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
- Filter Keys – Hou die regter SHIFT vir 12 sekondes ingedruk
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Wys Desktop
- WINDOWS+E – Begin Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen op nuwer Windows-weergawes
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Wissel volskerm binne Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Swipes

- Swipe van die linkerkant na regs om alle oop Windows te sien, die KIOSK-app te minimaliseer en direk toegang tot die hele OS te verkry;
- Swipe van die regterkant na links om Action Center oop te maak, die KIOSK-app te minimaliseer en direk toegang tot die hele OS te verkry;
- Swipe vanaf die boonste rand om die titelbalk sigbaar te maak vir 'n app wat in volskermmodus oopgemaak is;
- Swipe vanaf onder na bo om die taakbalk in 'n volskerm-app te wys.

### Internet Explorer-truuks

#### 'Image Toolbar'

Dit is 'n nutsbalk wat links bo aan 'n image verskyn wanneer daarop geklik word. Jy sal Save, Print, Mailto en Open "My Pictures" in Explorer kan gebruik. Die Kiosk moet Internet Explorer gebruik.

#### Shell Protocol

Tik hierdie URLs om 'n Explorer-aansig te verkry:

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

Raadpleeg hierdie bladsy vir meer inligting: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Browser-truuks

Rugsteun-iKat-weergawes:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Skep 'n algemene dialoog met JavaScript en verkry toegang tot file explorer: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Bron: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gebare en knoppies

- Swipe op met vier (of vyf) vingers / Dubbeltik die Home-knoppie: Om die multitask-aansig te sien en App te verander
- Swipe in die een of ander rigting met vier of vyf vingers: Om na die volgende/vorige App te verander
- Knyp die skerm met vyf vingers / Raak die Home-knoppie / Swipe vinnig met 1 vinger vanaf die onderkant van die skerm opwaarts: Om toegang tot Home te verkry
- Swipe stadig met een vinger 1–2 duim vanaf die onderkant van die skerm: Die dock sal verskyn
- Swipe met 1 vinger van die bokant van die skerm afwaarts: Om jou kennisgewings te sien
- Swipe met 1 vinger vanaf die boonste regterhoek van die skerm afwaarts: Om iPad Pro se control centre te sien
- Swipe met 1 vinger 1–2 duim vanaf die linkerkant van die skerm: Om Today view te sien
- Swipe vinnig met 1 vinger vanaf die middel van die skerm na regs of links: Om na die volgende/vorige App te verander
- Druk en hou die On/**Off**/Sleep-knoppie in die boonste regterhoek van die **iPad +** Beweeg die Slide to **power off**-skuifbalk heeltemal na regs: Om af te skakel
- Druk die On/**Off**/Sleep-knoppie in die boonste regterhoek van die **iPad en die Home-knoppie vir 'n paar sekondes**: Om 'n harde afskakeling af te dwing
- Druk die On/**Off**/Sleep-knoppie in die boonste regterhoek van die **iPad en die Home-knoppie vinnig**: Om 'n skermskoot te neem wat links onder op die skerm sal verskyn. Druk albei knoppies baie kortliks terselfdertyd; as jy hulle ’n paar sekondes hou, sal 'n harde afskakeling uitgevoer word.<sup>[[3]](#references)</sup>

### Kortpaaie

Jy moet 'n iPad-sleutelbord of 'n USB-sleutelbordadapter hê. Slegs kortpaaie wat kan help om uit die toepassing te ontsnap, word hier gewys.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Hierdie kortpaaie is vir die visuele instellings en klankinstellings, afhangend van die gebruik van die iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Verduister skerm                                                              |
| F2       | Verhelder skerm                                                               |
| F7       | Gaan een liedjie terug                                                         |
| F8       | Speel/pouse                                                                     |
| F9       | Slaan liedjie oor                                                              |
| F10      | Demp                                                                           |
| F11      | Verlaag volume                                                                |
| F12      | Verhoog volume                                                                |
| ⌘ Space  | Wys 'n lys van beskikbare tale; om een te kies, tik weer die spasiebalk. |

#### iPad-navigasie

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gaan na Home                                            |
| ⌘⇧H (Command-Shift-H)                              | Gaan na Home                                            |
| ⌘ (Space)                                          | Maak Spotlight oop                                      |
| ⌘⇥ (Command-Tab)                                   | Lys die laaste tien gebruikte apps                     |
| ⌘\~                                                | Gaan na die laaste App                                  |
| ⌘⇧3 (Command-Shift-3)                              | Skermskoot (verskyn links onder om dit te stoor of daarop te reageer) |
| ⌘⇧4                                                | Neem 'n skermskoot en maak dit in die editor oop       |
| Druk en hou ⌘                                   | Lys van kortpaaie wat vir die App beskikbaar is         |
| ⌘⌥D (Command-Option/Alt-D)                         | Bring die dock na vore                                  |
| ^⌥H (Control-Option-H)                             | Home-knoppie                                             |
| ^⌥H H (Control-Option-H-H)                         | Wys multitask-balk                                      |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Terug-knoppie                                           |
| → (Right arrow)                                    | Volgende item                                           |
| ← (Left arrow)                                     | Vorige item                                             |
| ↑↓ (Up arrow, Down arrow)                          | Tik gelyktydig op die geselekteerde item                |
| ⌥ ↓ (Option-Down arrow)                            | Scroll af                                               |
| ⌥↑ (Option-Up arrow)                               | Scroll op                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Scroll links of regs                                    |
| ^⌥S (Control-Option-S)                             | Skakel VoiceOver-spraak aan of af                       |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Wissel na die vorige app                               |
| ⌘⇥ (Command-Tab)                                   | Wissel terug na die oorspronklike app                  |
| ←+→, then Option + ← or Option+→                   | Navigeer deur Dock                                     |

#### Safari-kortpaaie

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Maak Location oop                                 |
| ⌘T                      | Maak 'n nuwe tab oop                              |
| ⌘W                      | Maak die huidige tab toe                          |
| ⌘R                      | Verfris die huidige tab                           |
| ⌘.                      | Stop die laai van die huidige tab                 |
| ^⇥                      | Wissel na die volgende tab                        |
| ^⇧⇥ (Control-Shift-Tab) | Beweeg na die vorige tab                          |
| ⌘L                      | Kies die teksinvoer-/URL-veld om dit te wysig     |
| ⌘⇧T (Command-Shift-T)   | Maak die laaste geslote tab oop (kan verskeie kere gebruik word) |
| ⌘\[                     | Gaan een bladsy terug in jou blaaigeskiedenis      |
| ⌘]                      | Gaan een bladsy vorentoe in jou blaaigeskiedenis  |
| ⌘⇧R                     | Aktiveer Reader Mode                              |

#### Mail-kortpaaie

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Maak Location oop            |
| ⌘T                         | Maak 'n nuwe tab oop         |
| ⌘W                         | Maak die huidige tab toe     |
| ⌘R                         | Verfris die huidige tab      |
| ⌘.                         | Stop die laai van die huidige tab |
| ⌘⌥F (Command-Option/Alt-F) | Search in jou mailbox       |

## Verwysings

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
