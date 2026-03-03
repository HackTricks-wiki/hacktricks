# Kutoroka kutoka KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Kagua kifaa kimwili

| Sehemu       | Hatua                                                               |
| ------------ | ------------------------------------------------------------------- |
| Power button | Kuzima na kuwasha kifaa tena kunaweza kuonyesha skrini ya kuanza     |
| Power cable  | Angalia kama kifaa kinawasha upya wakati nguvu zikitolewa kwa muda mfupi |
| USB ports    | Unganisha keyboard ya nje ili uweze kutumia shortcuts zaidi         |
| Ethernet     | Skanning ya mtandao au sniffing inaweza kuwezesha matumizi mabaya zaidi |

## Angalia vitendo vinavyowezekana ndani ya programu ya GUI

**Dialogi za kawaida** ni chaguzi kama **kuhifadhi faili**, **kufungua faili**, kuchagua fonti, rangi... Zaidi yao zitatoa **utendaji kamili wa Explorer**. Hii inamaanisha kwamba utaweza kufikia uwezo wa Explorer endapo utaweza kufikia chaguzi hizi:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Unapaswa kukagua kama unaweza:

- Badilisha au tengeneza faili mpya
- Tengeneza viungo vya kielekezi (symbolic links)
- Pata ufikiaji wa maeneo yaliyozuiliwa
- Endesha programu nyingine

### Utekelezaji wa Amri

Labda **kutumia `Open with`** option\*\* unaweza kufungua/kuendesha aina fulani ya shell.

#### Windows

Kwa mfano _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ tafuta binaries zaidi ambazo zinaweza kutumika kuendesha amri (na kufanya vitendo visivyotarajiwa) hapa: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Zaidi hapa: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Kuepuka vizingiti vya njia

- **Environment variables**: Kuna environment variables nyingi zinazorejelea njia fulani
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Njia za kuungana na folda zilizosheheni. Jaribu kuungana na C$ ya mashine ya eneo ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: Tumia madialogi ya *Open/Save/Print-to-file* kama Explorer-lite. Jaribu `*.*` / `*.exe` katika uwanja la jina la faili, bonyeza-kulia folda kwa ajili ya **Open in new window**, na tumia **Properties → Open file location** kupanua urambazaji.
- **Create execution paths from dialogs**: Tengeneza faili mpya na uibadilishe jina hadi `.CMD` au `.BAT`, au tengeneza shortcut inayoelekeza kwa `%WINDIR%\System32` (au binary maalum kama `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Ikiwa unaweza kuvinjari hadi `cmd.exe`, jaribu **drag-and-drop** faili yoyote juu yake ili kuanzisha prompt. Ikiwa Task Manager inapatikana (`CTRL+SHIFT+ESC`), tumia **Run new task**.
- **Task Scheduler bypass**: Ikiwa shell za kuingilia zimefungwa lakini kupanga kazi inaruhusiwa, tengeneza task itakayotekeleza `cmd.exe` (GUI `taskschd.msc` au `schtasks.exe`).
- **Weak allowlists**: Ikiwa utekelezaji unaruhusiwa kwa **filename/extension**, badilisha jina la payload yako kwa jina linaloruhusiwa. Ikiwa inaruhusiwa kwa **directory**, nakili payload kwenye folda ya programu inayoruhusiwa kisha uite.
- **Find writable staging paths**: Anza na `%TEMP%` na orodhesha folda zinazoweza kuandikwa kwa kutumia Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Hatua inayofuata**: Ikiwa utapata shell, badilisha njia kwenda kwenye Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Pakua Binary zako

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Kupata filesystem kutoka kwa kivinjari

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Mifupi ya Kibodi

- Sticky Keys – Bonyeza SHIFT mara 5
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Shikilia NUMLOCK kwa sekunde 5
- Filter Keys – Shikilia SHIFT ya kulia kwa sekunde 12
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Onyesha Desktop
- WINDOWS+E – Fungua Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen kwenye matoleo mapya ya Windows
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Weka/tupilia nje skrini kamili ndani ya Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – Tabu Mpya
- CTRL+N – Internet Explorer – Ukurasa Mpya
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – RDP / Citrix mpya

### Kuteleza (Swipes)

- Teleza kutoka upande wa kushoto kwenda kulia kuona Windows zote zilizo wazi, kupunguza ukubwa wa app ya KIOSK na kufikia OS nzima moja kwa moja;
- Teleza kutoka upande wa kulia kwenda kushoto kufungua Action Center, kupunguza ukubwa wa app ya KIOSK na kufikia OS nzima moja kwa moja;
- Teleza kutoka kwenye ukingo wa juu kuleta mwambaa wa kichwa kuonekana kwa app iliyofunguliwa kwa skrini kamili;
- Teleza kutoka chini kwenda juu kuonyesha taskbar katika app ya skrini kamili.

### Mbinu za Internet Explorer

#### 'Image Toolbar'

Ni toolbar inayojitokeza upande wa juu-kushoto wa picha wakati inabonwa. Utaweza Kuokoa, Kuchapisha, Kutuma kwa barua (Mailto), Kufungua "My Pictures" katika Explorer. Kiosk inapaswa kutumia Internet Explorer.

#### Shell Protocol

Andika URL hizi ili kupata muonekano wa Explorer:

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

### Onyesha Extensions za Faili

Angalia ukurasa huu kwa maelezo zaidi: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Mbinu za kivinjari

Toleo za backup za iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Tengeneza dialog ya kawaida kwa kutumia JavaScript na upate file explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Mishale na vitufe

- Teleza juu kwa vidole vinne (au vitano) / Bonyeza mara mbili kitufe cha Home: Kuona muonekano wa multitask na kubadilisha App
- Teleza upande mmoja au mwingine kwa vidole vinne au vitano: Ili kubadilisha hadi App inayofuata/iliyopita
- Sukuma skrini kwa vidole vitano / Gusa kitufe cha Home / Teleza juu kwa kidole 1 kutoka chini ya skrini kwa mwendo wa haraka hadi juu: Kupata Home
- Teleza kidole 1 kutoka chini tu inchi 1-2 (polepole): Dock itaonekana
- Teleza chini kutoka juu ya skrini kwa kidole 1: Kuona taarifa zako (notifications)
- Teleza chini kwa kidole 1 kona ya juu-kulia ya skrini: Kuona control centre ya iPad Pro
- Teleza kidole 1 kutoka upande wa kushoto wa skrini inchi 1-2: Kuona Today view
- Teleza kwa haraka kidole 1 kutoka katikati ya skrini kwenda kulia au kushoto: Kubadilisha hadi App inayofuata/iliyopita
- Bonyeza na shikilia kitufe cha On/**Off**/Sleep kilicho kona ya juu-kulia ya **iPad +** Sukuma Slide to **power off** hadi mwisho wa kulia: Kuzima kifaa
- Bonyeza kitufe cha On/**Off**/Sleep kilicho kona ya juu-kulia ya **iPad na kitufe cha Home kwa sekunde chache**: Kufanya hard power off
- Bonyeza kitufe cha On/**Off**/Sleep kilicho kona ya juu-kulia ya **iPad na kitufe cha Home kwa haraka**: Kupiga screenshot ambayo itaonekana chini kushoto kwenye skrini. Bonyeza vitufe vyote kwa wakati mmoja kwa muda mfupi; ukivishikilia kwa sekunde chache itafanya hard power off.

### Mifupi

Unapaswa kuwa na kibodi ya iPad au adapter ya kibodi ya USB. Hapa tu zinaonyeshwa njia za mkato ambazo zinaweza kusaidia kutoroka kutoka kwa application.

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

#### Mifupi ya Mfumo

Mifupi hii ni kwa mipangilio ya kuona na sauti, kulingana na matumizi ya iPad.

| Shortcut | Kitendo                                                                          |
| -------- | -------------------------------------------------------------------------------- |
| F1       | Kupunguza mwangaza wa skrini                                                     |
| F2       | Kuongeza mwangaza wa skrini                                                      |
| F7       | Rudisha wimbo mmoja nyuma                                                         |
| F8       | Cheza/kuacha kucheza                                                              |
| F9       | Ruka wimbo                                                                       |
| F10      | Zima sauti                                                                        |
| F11      | Punguza kiasi                                                                      |
| F12      | Ongeza kiasi                                                                       |
| ⌘ Space  | Onyesha orodha ya lugha zinazopatikana; kuchagua moja, bonyeza space tena.      |

#### Urambazaji wa iPad

| Shortcut                                           | Kitendo                                                  |
| -------------------------------------------------- | -------------------------------------------------------- |
| ⌘H                                                 | Nenda Home                                               |
| ⌘⇧H (Command-Shift-H)                              | Nenda Home                                               |
| ⌘ (Space)                                          | Fungua Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Orodha ya apps kumi zilizotumika hivi karibuni           |
| ⌘\~                                                | Nenda kwenye App ya mwisho                                |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (inaonekana chini kushoto kuhifadhi au kuchukua hatua) |
| ⌘⇧4                                                | Screenshot na ifungue katika mhariri                      |
| Press and hold ⌘                                   | Orodha ya njia za mkato zinazopatikana kwa App           |
| ⌘⌥D (Command-Option/Alt-D)                         | Inaonyesha dock                                           |
| ^⌥H (Control-Option-H)                             | Kitufe cha Home                                           |
| ^⌥H H (Control-Option-H-H)                         | Onyesha mwambaa wa multitask                              |
| ^⌥I (Control-Option-i)                             | Chagua kipengee                                           |
| Escape                                             | Kitufe cha kurudi                                         |
| → (Right arrow)                                    | Kipengee kinachofuata                                     |
| ← (Left arrow)                                     | Kipengee kilichopita                                     |
| ↑↓ (Up arrow, Down arrow)                          | Gusa kitu kilichochaguliwa mara moja                      |
| ⌥ ↓ (Option-Down arrow)                            | Skroli chini                                              |
| ⌥↑ (Option-Up arrow)                               | Skroli juu                                                |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Skroli kushoto au kulia                                   |
| ^⌥S (Control-Option-S)                             | Washa au zima VoiceOver speech                            |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Badilisha kwenda app iliyotumika kabla                    |
| ⌘⇥ (Command-Tab)                                   | Rudisha kwenda app ya awali                               |
| ←+→, then Option + ← or Option+→                   | Pitia kupitia Dock                                        |

#### Mifupi ya Safari

| Shortcut                | Kitendo                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Fungua Location                                   |
| ⌘T                      | Fungua tabu mpya                                  |
| ⌘W                      | Funga tabu ya sasa                                |
| ⌘R                      | Refresh tabu ya sasa                              |
| ⌘.                      | Kuacha kupakia tabu ya sasa                       |
| ^⇥                      | Badilisha kwenda tabu inayofuata                   |
| ^⇧⇥ (Control-Shift-Tab) | Rekebisha kwenda tabu iliyopita                   |
| ⌘L                      | Chagua uwanja wa maandishi/URL ili kuuhariri      |
| ⌘⇧T (Command-Shift-T)   | Fungua tabu iliyofungwa hivi karibuni (inaweza kutumika mara kadhaa) |
| ⌘\[                     | Rudi ukurasa mmoja nyuma katika historia ya kivinjari |
| ⌘]                      | Nenda mbele ukurasa mmoja katika historia ya kivinjari |
| ⌘⇧R                     | Washa Reader Mode                                  |

#### Mifupi ya Mail

| Shortcut                   | Kitendo                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Fungua Location               |
| ⌘T                         | Fungua tabu mpya              |
| ⌘W                         | Funga tabu ya sasa            |
| ⌘R                         | Refresh tabu ya sasa         |
| ⌘.                         | Kuacha kupakia tabu ya sasa  |
| ⌘⌥F (Command-Option/Alt-F) | Tafuta katika mailbox yako    |

## Marejeleo

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
