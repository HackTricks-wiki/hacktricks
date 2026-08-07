# KIOSKs से बाहर निकलना

{{#include ../banners/hacktricks-training.md}}

---

## भौतिक device की जाँच करें

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | device को बंद करके फिर से चालू करने पर start screen दिखाई दे सकती है    |
| Power cable  | जाँचें कि थोड़ी देर के लिए power कटने पर device reboot होता है या नहीं |
| USB ports    | अधिक shortcuts के लिए physical keyboard connect करें                      |
| Ethernet     | Network scan या sniffing से आगे exploitation संभव हो सकता है           |

## GUI application के अंदर संभावित actions की जाँच करें

**Common Dialogs** वे options होते हैं जिनमें **file save करना**, **file open करना**, font, color आदि select करना शामिल है। इनमें से अधिकांश **full Explorer functionality प्रदान करेंगे**। इसका मतलब है कि यदि आप इन options तक पहुँच सकते हैं, तो आप Explorer functionalities access कर पाएँगे:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

आपको जाँच करनी चाहिए कि क्या आप:

- नई files modify या create कर सकते हैं
- Symbolic links create कर सकते हैं
- Restricted areas तक access प्राप्त कर सकते हैं
- अन्य apps execute कर सकते हैं

### Command Execution

शायद **`Open with` option** का उपयोग करके आप किसी प्रकार का shell open/execute कर सकें।

#### Windows

उदाहरण के लिए _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ commands execute करने और unexpected actions करने के लिए उपयोग किए जा सकने वाले अन्य binaries यहाँ खोजें: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ अधिक जानकारी यहाँ: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Path restrictions को bypass करना

- **Environment variables**: ऐसे बहुत से environment variables होते हैं जो किसी path की ओर point करते हैं
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (नई session open करना), CTRL+R (Commands execute करना), CTRL+SHIFT+ESC (Task Manager), Windows+E (explorer open करना), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Shared folders से connect करने के लिए paths। आपको local machine के C$ से connect करने का प्रयास करना चाहिए ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: *Open/Save/Print-to-file* dialogs को Explorer-lite की तरह उपयोग करें। Filename field में `*.*` / `*.exe` आज़माएँ, folders पर right-click करके **Open in new window** चुनें, और navigation को विस्तृत करने के लिए **Properties → Open file location** का उपयोग करें।<sup>[[1]](#references)</sup>
- **Create execution paths from dialogs**: एक नई file create करके उसका नाम `.CMD` या `.BAT` में बदलें, या `%WINDIR%\System32` (या किसी specific binary जैसे `%WINDIR%\System32\cmd.exe`) की ओर point करने वाला shortcut create करें।
- **Shell launch pivots**: यदि आप `cmd.exe` तक browse कर सकते हैं, तो prompt launch करने के लिए किसी भी file को उस पर **drag-and-drop** करने का प्रयास करें। यदि Task Manager उपलब्ध है (`CTRL+SHIFT+ESC`), तो **Run new task** का उपयोग करें।
- **Task Scheduler bypass**: यदि interactive shells blocked हैं लेकिन scheduling allowed है, तो `cmd.exe` run करने के लिए एक task create करें (GUI `taskschd.msc` या `schtasks.exe`)।
- **Weak allowlists**: यदि execution **filename/extension** के आधार पर allowed है, तो अपने payload का नाम किसी permitted name में बदल दें। यदि यह **directory** के आधार पर allowed है, तो payload को किसी allowed program folder में copy करके वहीं run करें।
- **Find writable staging paths**: `%TEMP%` से शुरुआत करें और Sysinternals AccessChk से writeable folders enumerate करें।
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **अगला चरण**: यदि आपको shell मिल जाता है, तो Windows LPE checklist पर जाएँ:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### अपने Binaries Download करें

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Browser से filesystem Access करना

| PATH                | PATH              | PATH               | PATH               |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### शॉर्टकट्स

- Sticky Keys – SHIFT को 5 बार दबाएँ
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCK को 5 सेकंड तक दबाकर रखें
- Filter Keys – दाएँ SHIFT को 12 सेकंड तक दबाकर रखें
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Desktop दिखाएँ
- WINDOWS+E – Windows Explorer Launch करें
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – नए Windows versions पर Splash screen
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Internet Explorer में full screen Toggle करें
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – File खोलें
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Swipes

- सभी खुले हुए Windows देखने के लिए बाईं ओर से दाईं ओर Swipe करें, KIOSK app को minimize करके पूरे OS को सीधे Access करें;
- Action Center खोलने के लिए दाईं ओर से बाईं ओर Swipe करें, KIOSK app को minimize करके पूरे OS को सीधे Access करें;
- full screen mode में खुले app के लिए title bar दिखाने हेतु ऊपरी edge से अंदर की ओर Swipe करें;
- full screen app में taskbar दिखाने के लिए नीचे से ऊपर की ओर Swipe करें।

### Internet Explorer Tricks

#### 'Image Toolbar'

यह एक toolbar है जो image पर click करने पर उसके ऊपरी-बाएँ दिखाई देती है। आप Explorer में Save, Print, Mailto और "My Pictures" Open कर सकेंगे। Kiosk में Internet Explorer का उपयोग होना चाहिए।

#### Shell Protocol

Explorer view प्राप्त करने के लिए ये URLs Type करें:

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

### File Extensions दिखाएँ

अधिक जानकारी के लिए यह page देखें: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Browsers tricks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript का उपयोग करके एक common dialog बनाएँ और file explorer Access करें: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures और buttons

- चार (या पाँच) fingers से ऊपर की ओर Swipe करें / Home button को Double-tap करें: multitask view देखने और App बदलने के लिए
- चार या पाँच fingers से किसी भी दिशा में Swipe करें: next/last App पर जाने के लिए
- पाँच fingers से screen को Pinch करें / Home button Touch करें / screen के निचले भाग से 1 finger को तेज़ी से ऊपर की ओर Swipe करें: Home Access करने के लिए
- screen के निचले भाग से 1 finger को केवल 1-2 inches धीरे-धीरे ऊपर की ओर Swipe करें: dock दिखाई देगा
- display के ऊपरी भाग से 1 finger नीचे की ओर Swipe करें: notifications देखने के लिए
- screen के ऊपरी-दाएँ corner पर 1 finger से नीचे की ओर Swipe करें: iPad Pro का control centre देखने के लिए
- screen के बाएँ भाग से 1 finger को 1-2 inches Swipe करें: Today view देखने के लिए
- screen के centre से 1 finger को तेज़ी से दाईं या बाईं ओर Swipe करें: next/last App पर जाने के लिए
- **iPad +** के ऊपरी-दाएँ corner पर On/**Off**/Sleep button को दबाकर रखें और Slide to **power off** slider को पूरी तरह दाईं ओर Move करें: power off करने के लिए
- **iPad के On/**Off**/Sleep button और Home button को कुछ seconds तक दबाकर रखें**: hard power off force करने के लिए
- **iPad के On/**Off**/Sleep button और Home button को जल्दी से दबाएँ**: display के निचले-बाएँ भाग में दिखाई देने वाला screenshot लेने के लिए। दोनों buttons को एक साथ बहुत थोड़ी देर दबाएँ; यदि आप उन्हें कुछ seconds तक दबाकर रखेंगे, तो hard power off किया जाएगा।<sup>[[3]](#references)</sup>

### शॉर्टकट्स

आपके पास iPad keyboard या USB keyboard adaptor होना चाहिए। यहाँ केवल वे shortcuts दिखाए जाएँगे जो application से escape करने में मदद कर सकते हैं।<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

ये shortcuts iPad के उपयोग के आधार पर visual settings और sound settings के लिए हैं।

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Sscreen Dim करें                                                               |
| F2       | screen Brighten करें                                                           |
| F7       | एक song पीछे जाएँ                                                              |
| F8       | Play/pause                                                                     |
| F9       | song Skip करें                                                                 |
| F10      | Mute                                                                           |
| F11      | volume Decrease करें                                                           |
| F12      | volume Increase करें                                                           |
| ⌘ Space  | उपलब्ध languages की list Display करें; किसी language को चुनने के लिए space bar को फिर से tap करें। |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Home पर जाएँ                                            |
| ⌘⇧H (Command-Shift-H)                              | Home पर जाएँ                                            |
| ⌘ (Space)                                          | Spotlight Open करें                                     |
| ⌘⇥ (Command-Tab)                                   | पिछली दस उपयोग की गई apps की list                      |
| ⌘\~                                                | पिछली App पर जाएँ                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (save या उस पर कार्य करने के लिए नीचे बाएँ hover करता है) |
| ⌘⇧4                                                | Screenshot लेकर उसे editor में Open करें               |
| Press and hold ⌘                                   | App के लिए उपलब्ध shortcuts की list                   |
| ⌘⌥D (Command-Option/Alt-D)                         | dock दिखाता है                                         |
| ^⌥H (Control-Option-H)                             | Home button                                             |
| ^⌥H H (Control-Option-H-H)                         | multitask bar दिखाएँ                                    |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Back button                                             |
| → (Right arrow)                                    | Next item                                               |
| ← (Left arrow)                                     | Previous item                                           |
| ↑↓ (Up arrow, Down arrow)                          | Selected item को simultaneously tap करें               |
| ⌥ ↓ (Option-Down arrow)                            | Scroll down                                             |
| ⌥↑ (Option-Up arrow)                               | Scroll up                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Scroll left or right                                    |
| ^⌥S (Control-Option-S)                             | VoiceOver speech को on या off करें                     |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Previous app पर Switch करें                             |
| ⌘⇥ (Command-Tab)                                   | Original app पर वापस Switch करें                       |
| ←+→, then Option + ← or Option+→                   | Dock में Navigate करें                                  |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Location Open करें                                |
| ⌘T                      | नया tab Open करें                                |
| ⌘W                      | Current tab Close करें                           |
| ⌘R                      | Current tab Refresh करें                         |
| ⌘.                      | Current tab की loading Stop करें                 |
| ^⇥                      | Next tab पर Switch करें                           |
| ^⇧⇥ (Control-Shift-Tab) | Previous tab पर जाएँ                             |
| ⌘L                      | Modify करने के लिए text input/URL field Select करें |
| ⌘⇧T (Command-Shift-T)   | Last closed tab Open करें (कई बार उपयोग किया जा सकता है) |
| ⌘\[                     | Browsing history में एक page पीछे जाएँ           |
| ⌘]                      | Browsing history में एक page आगे जाएँ            |
| ⌘⇧R                     | Reader Mode Activate करें                        |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Location Open करें            |
| ⌘T                         | नया tab Open करें             |
| ⌘W                         | Current tab Close करें        |
| ⌘R                         | Current tab Refresh करें      |
| ⌘.                         | Current tab की loading Stop करें |
| ⌘⌥F (Command-Option/Alt-F) | अपने mailbox में Search करें   |

## References

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
