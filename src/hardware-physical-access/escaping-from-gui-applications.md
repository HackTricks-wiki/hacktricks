# Escaping from KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Kagua kifaa halisi

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Kitufe cha kuwasha | Kuzima na kuwasha kifaa tena kunaweza kuonyesha skrini ya mwanzo    |
| Kebo ya umeme  | Kagua kama kifaa kina-reboot umeme unapokatwa kwa muda mfupi |
| Milango ya USB    | Unganisha keyboard halisi yenye shortcuts zaidi                      |
| Ethernet     | Network scan au sniffing inaweza kuwezesha exploitation zaidi           |

## Kagua actions zinazowezekana ndani ya GUI application

**Common Dialogs** ni chaguo kama **kuhifadhi file**, **kufungua file**, kuchagua font, color... Nyingi kati yao **zitatoa functionality kamili ya Explorer**. Hii inamaanisha utaweza kufikia functionalities za Explorer ikiwa unaweza kufikia chaguo hizi:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Unapaswa kukagua kama unaweza:

- Modify au create files mpya
- Create symbolic links
- Kupata access kwenye maeneo yaliyowekewa restrictions
- Execute apps nyingine

### Command Execution

Labda kwa **kutumia option ya `Open with`**\*\* unaweza kufungua/execute aina fulani ya shell.

#### Windows

Kwa mfano _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pata binaries zaidi zinazoweza kutumika ku-execute commands (na kufanya actions zisizotarajiwa) hapa: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Zaidi hapa: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassing path restrictions

- **Environment variables**: Kuna environment variables nyingi zinazoelekeza kwenye path fulani
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Paths za kuunganisha kwenye shared folders. Unapaswa kujaribu kuunganisha kwenye C$ ya local machine ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: Tumia dialogs za *Open/Save/Print-to-file* kama Explorer-lite. Jaribu `*.*` / `*.exe` kwenye filename field, bofya kulia folders ili kupata **Open in new window**, na tumia **Properties → Open file location** kupanua navigation.<sup>[[1]](#references)</sup>
- **Create execution paths from dialogs**: Create file mpya na uipe jina upya iwe `.CMD` au `.BAT`, au create shortcut inayoelekeza kwenye `%WINDIR%\System32` (au binary maalum kama `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Ikiwa unaweza ku-browse hadi `cmd.exe`, jaribu **drag-and-drop** file yoyote juu yake ili kuzindua prompt. Ikiwa Task Manager inapatikana (`CTRL+SHIFT+ESC`), tumia **Run new task**.
- **Task Scheduler bypass**: Ikiwa interactive shells zimezuiwa lakini scheduling inaruhusiwa, create task ya ku-run `cmd.exe` (GUI `taskschd.msc` au `schtasks.exe`).
- **Weak allowlists**: Ikiwa execution inaruhusiwa kwa **filename/extension**, rename payload yako iwe na jina linaloruhusiwa. Ikiwa inaruhusiwa kwa **directory**, copy payload kwenye program folder inayoruhusiwa na ui-run humo.
- **Find writable staging paths**: Anza na `%TEMP%` na enumerate folders zinazoweza kuandikwa kwa Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Hatua inayofuata**: Ukipata shell, nenda kwenye checklist ya Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Pakua Binaries Zako

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Kufikia filesystem kutoka kwenye browser

| PATH                | PATH              | PATH               | PATH               |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Njia za mkato

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
- F11 – Washa/zima full screen ndani ya Internet Explorer
- CTRL+H – Historia ya Internet Explorer
- CTRL+T – Internet Explorer – Tab Mpya
- CTRL+N – Internet Explorer – Ukurasa Mpya
- CTRL+O – Fungua File
- CTRL+S – Hifadhi CTRL+N – RDP / Citrix Mpya

### Swipes

- Swipe kutoka upande wa kushoto kwenda kulia ili kuona Windows zote zilizo wazi, kupunguza KIOSK app na kufikia OS nzima moja kwa moja;
- Swipe kutoka upande wa kulia kwenda kushoto ili kufungua Action Center, kupunguza KIOSK app na kufikia OS nzima moja kwa moja;
- Swipe kutoka ukingo wa juu ili kufanya title bar ionekane kwa app iliyofunguliwa katika full screen mode;
- Swipe kwenda juu kutoka chini ili kuonyesha taskbar katika full screen app.

### Tricks za Internet Explorer

#### 'Image Toolbar'

Ni toolbar inayoonekana upande wa juu kushoto wa picha inapobofya picha hiyo. Utaweza kuhifadhi, kuchapisha, kutuma kwa barua pepe, na kufungua "My Pictures" katika Explorer. Kiosk lazima iwe inatumia Internet Explorer.

#### Shell Protocol

Andika URLs hizi ili kupata mwonekano wa Explorer:

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

### Onyesha File Extensions

Angalia ukurasa huu kwa maelezo zaidi: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Tricks za browsers

Matoleo ya zamani ya iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Unda common dialog kwa kutumia JavaScript na ufikie file explorer: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures na vitufe

- Swipe kwenda juu kwa vidole vinne (au vitano) / Bofya kitufe cha Home mara mbili: Kuona mwonekano wa multitask na kubadilisha App
- Swipe upande mmoja au mwingine kwa vidole vinne au vitano: Kubadilisha kwenda App inayofuata/iliyotangulia
- Bana screen kwa vidole vitano / Gusa kitufe cha Home / Swipe kwenda juu kwa kidole 1 kutoka chini ya screen kwa mwendo wa haraka: Kufikia Home
- Swipe kwa kidole kimoja kutoka chini ya screen kwa umbali wa inchi 1-2 tu (polepole): Dock itaonekana
- Swipe chini kutoka juu ya display kwa kidole 1: Kuona notifications zako
- Swipe chini kwa kidole 1 kutoka kona ya juu kulia ya screen: Kuona control centre ya iPad Pro
- Swipe kwa kidole 1 kutoka upande wa kushoto wa screen kwa inchi 1-2: Kuona Today view
- Swipe haraka kwa kidole 1 kutoka katikati ya screen kwenda kulia au kushoto: Kubadilisha kwenda App inayofuata/iliyotangulia
- Bonyeza na ushikilie kitufe cha On/**Off**/Sleep upande wa juu kulia wa **iPad +** Sogeza slider ya **power off** hadi mwisho kulia: Kuzima
- Bonyeza kitufe cha On/**Off**/Sleep upande wa juu kulia wa **iPad na kitufe cha Home kwa sekunde chache**: Kulazimisha kuzima kabisa
- Bonyeza kitufe cha On/**Off**/Sleep upande wa juu kulia wa **iPad na kitufe cha Home kwa haraka**: Kupiga screenshot itakayoonekana chini kushoto mwa display. Bonyeza vitufe vyote viwili kwa wakati mmoja kwa muda mfupi sana; ukiwashikilia kwa sekunde chache, kuzima kabisa kutafanyika.<sup>[[3]](#references)</sup>

### Njia za mkato

Unapaswa kuwa na keyboard ya iPad au USB keyboard adaptor. Ni njia za mkato pekee zinazoweza kusaidia kutoka kwenye app zitakazoonyeshwa hapa.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

#### Njia za mkato za mfumo

Njia hizi za mkato ni za mipangilio ya mwonekano na mipangilio ya sauti, kutegemea matumizi ya iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Punguza mwangaza wa screen                                                     |
| F2       | Ongeza mwangaza wa screen                                                      |
| F7       | Rudi kwenye wimbo mmoja                                                        |
| F8       | Play/pause                                                                     |
| F9       | Ruka wimbo                                                                     |
| F10      | Nyamazisha                                                                     |
| F11      | Punguza volume                                                                 |
| F12      | Ongeza volume                                                                  |
| ⌘ Space  | Onyesha orodha ya lugha zinazopatikana; ili kuchagua moja, gusa space bar tena. |

#### Navigation ya iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Nenda Home                                              |
| ⌘⇧H (Command-Shift-H)                              | Nenda Home                                              |
| ⌘ (Space)                                          | Fungua Spotlight                                        |
| ⌘⇥ (Command-Tab)                                   | Orodhesha apps kumi zilizotumika mwisho                 |
| ⌘\~                                                | Nenda kwenye App ya mwisho                               |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (inaonekana chini kushoto ili kuihifadhi au kuifanyia kitendo) |
| ⌘⇧4                                                | Piga screenshot na uifungue kwenye editor                |
| Bonyeza na ushikilie ⌘                              | Orodha ya njia za mkato zinazopatikana kwa App           |
| ⌘⌥D (Command-Option/Alt-D)                         | Huonyesha dock                                           |
| ^⌥H (Control-Option-H)                             | Kitufe cha Home                                          |
| ^⌥H H (Control-Option-H-H)                         | Onyesha multitask bar                                    |
| ^⌥I (Control-Option-i)                             | Item chooser                                             |
| Escape                                             | Kitufe cha kurudi                                        |
| → (Right arrow)                                    | Item inayofuata                                          |
| ← (Left arrow)                                     | Item iliyotangulia                                       |
| ↑↓ (Up arrow, Down arrow)                          | Gusa item iliyochaguliwa kwa wakati mmoja                |
| ⌥ ↓ (Option-Down arrow)                            | Sogeza chini                                             |
| ⌥↑ (Option-Up arrow)                               | Sogeza juu                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Sogeza kushoto au kulia                                  |
| ^⌥S (Control-Option-S)                             | Washa au zima sauti ya VoiceOver                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Hamia kwenye app iliyotangulia                            |
| ⌘⇥ (Command-Tab)                                   | Rudi kwenye app ya awali                                 |
| ←+→, then Option + ← or Option+→                   | Navigate kupitia Dock                                    |

#### Njia za mkato za Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Fungua Location                                    |
| ⌘T                      | Fungua tab mpya                                   |
| ⌘W                      | Funga tab ya sasa                                 |
| ⌘R                      | Refresh tab ya sasa                               |
| ⌘.                      | Simamisha kupakia tab ya sasa                     |
| ^⇥                      | Hamia kwenye tab inayofuata                       |
| ^⇧⇥ (Control-Shift-Tab) | Hamia kwenye tab iliyotangulia                    |
| ⌘L                      | Chagua sehemu ya kuingiza text/URL ili kuibadilisha |
| ⌘⇧T (Command-Shift-T)   | Fungua tab iliyofungwa mwisho (inaweza kutumiwa mara kadhaa) |
| ⌘\[                     | Rudi ukurasa mmoja kwenye historia ya browsing    |
| ⌘]                      | Nenda mbele ukurasa mmoja kwenye historia ya browsing |
| ⌘⇧R                     | Washa Reader Mode                                  |

#### Njia za mkato za Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Fungua Location                |
| ⌘T                         | Fungua tab mpya               |
| ⌘W                         | Funga tab ya sasa             |
| ⌘R                         | Refresh tab ya sasa           |
| ⌘.                         | Simamisha kupakia tab ya sasa |
| ⌘⌥F (Command-Option/Alt-F) | Search kwenye mailbox yako    |

## References

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
