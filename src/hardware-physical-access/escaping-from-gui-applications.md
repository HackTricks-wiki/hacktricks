# Kutoroka kutoka kwa KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Angalia kifaa kimwili

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Kuzima na kuwasha kifaa tena kunaweza kufichua skrini ya kuanzisha  |
| Power cable  | Angalia kama kifaa kinaanzisha upya wakati umeme ukikatika kwa muda mfupi |
| USB ports    | Unganisha kibodi ya nje yenye njia za mkato zaidi                  |
| Ethernet     | Skanning ya mtandao au sniffing inaweza kuwezesha matumizi zaidi    |

## Angalia hatua zinazowezekana ndani ya programu ya GUI

**Dialogi za kawaida** ni zile chaguzi za **kuhifadhi faili**, **kufungua faili**, kuchagua fonti, rangi... Zingine nyingi zitatoa **utendakazi kamili wa Explorer**. Hii inamaanisha utaweza kufikia utendakazi wa Explorer ikiwa unaweza kufikia chaguzi hizi:

- Funga/Funga kama
- Fungua/Fungua na
- Chapisha
- Hamisha/Ingiza
- Tafuta
- Skani

Unapaswa kuangalia ikiwa unaweza:

- Kurekebisha au kuunda faili mpya
- Kuunda symbolic links
- Kupata ufikiaji wa maeneo yaliyotiwa vikwazo
- Kuendesha programu nyingine

### Utekelezaji wa Amri

Labda **using a `Open with`** option\*\* unaweza kufungua/kuendesha aina fulani ya shell.

#### Windows

Kwa mfano _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pata binaries zaidi zinazoweza kutumika kutekeleza amri (na kufanya vitendo visivyotarajiwa) hapa: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Zaidi hapa: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Kukwepa vikwazo vya njia

- **Environment variables**: Kuna environment variables nyingi zinazoelekeza kwenye njia fulani
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Njia za mkato**: CTRL+N (fungua kikao kipya), CTRL+R (Tekeleza Amri), CTRL+SHIFT+ESC (Task Manager), Windows+E (fungua Explorer), CTRL-B, CTRL-I (Vipendwa), CTRL-H (Historia), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Hifadhi Kama)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Njia za kuunganishwa na folda zilizosambazwa. Unapaswa kujaribu kuunganishwa na C$ ya mashine ya ndani ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: Tumia *Open/Save/Print-to-file* dialogi kama Explorer-lite. Jaribu `*.*` / `*.exe` katika uwanja wa jina la faili, bonyeza kulia kwenye folda kwa **Open in new window**, na tumia **Properties → Open file location** ili kupanua urambazaji.
- **Create execution paths from dialogs**: Unda faili mpya na uibadilishe jina kuwa `.CMD` au `.BAT`, au unda shortcut inayorejea `%WINDIR%\System32` (au binary maalum kama `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Ikiwa unaweza kuvinjari hadi `cmd.exe`, jaribu **drag-and-drop** faili yoyote juu yake ili kuanzisha prompt. Iki Task Manager inapatikana (`CTRL+SHIFT+ESC`), tumia **Run new task**.
- **Task Scheduler bypass**: Ikiwa shells za kuingilia zimezuiwa lakini upangaji kazi unaruhusiwa, unda task ili iendeshe `cmd.exe` (GUI `taskschd.msc` au `schtasks.exe`).
- **Weak allowlists**: Ikiwa utekelezaji unaruhusiwa kwa **filename/extension**, badilisha jina la payload yako kuwa jina linaloruhusiwa. Ikiwa inaruhusiwa kwa **directory**, nakili payload kwenye folda ya programu iliyoruhusiwa na iendeshe huko.
- **Find writable staging paths**: Anza na `%TEMP%` na orodhesha folda zinazoweza kuandikwa kwa kutumia Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Next step**: Ikiwa unapata shell, pinda kwenye Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Download Your Binaries

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accessing filesystem from the browser

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### ShortCuts

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
- SHIFT+F10 – Menyu ya muktadha (Context Menu)
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen kwenye matoleo mapya ya Windows
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Geuza kwenye skrini kamili ndani ya Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Swipes

- Swipe kutoka upande wa kushoto hadi kulia ili uone Windows zote zilizo wazi, kupunguza programu ya KIOSK na kupata OS nzima moja kwa moja;
- Swipe kutoka upande wa kulia hadi kushoto kufungua Action Center, kupunguza programu ya KIOSK na kupata OS nzima moja kwa moja;
- Swipe kutoka juu ya kingo ili kufanya title bar ionekane kwa app iliyofunguliwa kwa skrini kamili;
- Swipe kutoka chini kwenda juu kuonyesha taskbar katika app ya skrini kamili.

### Internet Explorer Tricks

#### 'Image Toolbar'

Ni toolbar inayojitokeza upande wa juu-kushoto wa picha wakati inabonyezwa. Utakuwa na uwezo wa Save, Print, Mailto, Fungua "My Pictures" katika Explorer. Kiosk inahitaji kutumia Internet Explorer.

#### Shell Protocol

Andika hizi URLs kupata mtazamo wa Explorer:

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

### Show File Extensions

Angalia ukurasa huu kwa taarifa zaidi: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browsers tricks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Create a common dialog using JavaScript and access file explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures and bottoms

- Swipe up kwa vidole vinne (au vitano) / Double-tap kitufe cha Home: Kuona multitask view na kubadilisha App
- Swipe kwa njia moja au nyingine kwa vidole vinne au vitano: Ili kubadilisha kwa App inayofuata/iliyo nyuma
- Pinch skrini kwa vidole vitano / Gusa kitufe cha Home / Swipe up kwa kidole 1 kutoka chini ya skrini kwa mwendo wa haraka kwenda juu: Kufikia Home
- Swipe kidole 1 kutoka chini ya skrini kwa umbali wa inchi 1-2 (polepole): Dock itaonekana
- Swipe chini kutoka juu ya display kwa kidole 1: Kuona notifications zako
- Swipe chini kwa kidole 1 kona ya juu-kulia ya skrini: Kuona control centre ya iPad Pro
- Swipe kidole 1 kutoka upande wa kushoto wa skrini umbali wa inchi 1-2: Kuona Today view
- Swipe haraka kidole 1 kutoka katikati ya skrini kwenda kulia au kushoto: Kubadilisha kwa App inayofuata/iliyo nyuma
- Bonyeza na ushikilie kitufe cha On/**Off**/Sleep upande wa juu-kulia wa **iPad +** Sukuma Slide to **power off** hadi mwisho wa kulia: Kuzima kifaa
- Bonyeza kitufe cha On/**Off**/Sleep upande wa juu-kulia wa **iPad na kitufe cha Home kwa sekunde chache**: Kufanyika hard power off uliyolazimishwa
- Bonyeza kitufe cha On/**Off**/Sleep upande wa juu-kulia wa **iPad na kitufe cha Home kwa haraka**: Kuchukua screenshot ambayo itaonekana chini kushoto ya display. Bonyeza vitufe vyote kwa wakati mmoja kwa muda mfupi; ikiwa utavishikilia sekunde chache kutatokea hard power off.

### Shortcuts

Unapaswa kuwa na kibodi ya iPad au adapter ya kibodi ya USB. Hapa tutaonyesha tu shortcuts ambazo zinaweza kusaidia kutoroka kutoka kwa application.

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

#### System shortcuts

Hizi ni shortcuts kwa mipangilio ya kuona na sauti, kulingana na matumizi ya iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Dim Screen                                                                     |
| F2       | Angazia screen                                                                  |
| F7       | Rejea wimbo uliopita                                                            |
| F8       | Play/pause                                                                      |
| F9       | Ruka wimbo                                                                       |
| F10      | Mute                                                                            |
| F11      | Punguza volume                                                                   |
| F12      | Ongeza volume                                                                     |
| ⌘ Space  | Onyesha orodha ya lugha zinazopatikana; kuchagua moja, bonyeza space tena.     |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Nenda Home                                              |
| ⌘⇧H (Command-Shift-H)                              | Nenda Home                                              |
| ⌘ (Space)                                          | Fungua Spotlight                                        |
| ⌘⇥ (Command-Tab)                                   | Orodha ya apps kumi zilizotumika hivi karibuni         |
| ⌘\~                                                | Nenda kwa App ya mwisho                                  |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (itaonekana chini kushoto kuhifadhi au kuchukua hatua) |
| ⌘⇧4                                                | Screenshot na ifungue katika editor                     |
| Press and hold ⌘                                   | Orodha ya shortcuts zinazopatikana kwa App              |
| ⌘⌥D (Command-Option/Alt-D)                         | Inaonyesha dock                                          |
| ^⌥H (Control-Option-H)                             | Kitufe cha Home                                         |
| ^⌥H H (Control-Option-H-H)                         | Onyesha multitask bar                                   |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Kitufe cha Back                                         |
| → (Right arrow)                                    | Kitu kinachofuata                                       |
| ← (Left arrow)                                     | Kitu kilichopita                                        |
| ↑↓ (Up arrow, Down arrow)                          | Bonyeza mara moja kitu kilichochaguliwa                  |
| ⌥ ↓ (Option-Down arrow)                            | Susurutisha chini                                       |
| ⌥↑ (Option-Up arrow)                               | Susurutisha juu                                         |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Susurutisha kushoto au kulia                            |
| ^⌥S (Control-Option-S)                             | Weka/ondoa VoiceOver speech                             |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Badilisha kwenda app iliyotumika kabla                   |
| ⌘⇥ (Command-Tab)                                   | Rejea kwenye app ya awali                               |
| ←+→, then Option + ← or Option+→                   | Navegatia kupitia Dock                                  |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Fungua Location                                  |
| ⌘T                      | Fungua tab mpya                                  |
| ⌘W                      | Funga tab ya sasa                                |
| ⌘R                      | Refresh tab ya sasa                              |
| ⌘.                      | Acha upakuaji wa tab ya sasa                     |
| ^⇥                      | Badilisha kwenda tab ifuatayo                     |
| ^⇧⇥ (Control-Shift-Tab) | Rudi kwenye tab iliyotangulia                    |
| ⌘L                      | Chagua sehemu ya text/URL ili kuirekebisha       |
| ⌘⇧T (Command-Shift-T)   | Fungua tab iliyofungwa hivi karibuni (inaweza kutumika mara nyingi) |
| ⌘\[                     | Rudi ukurasa mmoja katika history ya browsing     |
| ⌘]                      | Nenda mbele ukurasa mmoja katika history ya browsing |
| ⌘⇧R                     | Washa Reader Mode                                 |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Fungua Location              |
| ⌘T                         | Fungua tab mpya              |
| ⌘W                         | Funga tab ya sasa            |
| ⌘R                         | Refresh tab ya sasa          |
| ⌘.                         | Acha upakuaji wa tab ya sasa |
| ⌘⌥F (Command-Option/Alt-F) | Tafuta katika mailbox yako   |

## References

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
