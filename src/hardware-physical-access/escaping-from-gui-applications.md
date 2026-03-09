# KIOSKs से बाहर निकलना

{{#include ../banners/hacktricks-training.md}}

---

## भौतिक डिवाइस की जाँच

| घटक         | कार्रवाई                                                            |
| ------------ | ------------------------------------------------------------------ |
| Power button | डिवाइस को बंद करके फिर चालू करने पर स्टार्ट स्क्रीन उजागर हो सकती है |
| Power cable  | जाँचें कि क्या पावर थोड़ी देर के लिए कटने पर डिवाइस रीबूट होता है   |
| USB ports    | अधिक शॉर्टकट्स के साथ भौतिक कीबोर्ड कनेक्ट करें                    |
| Ethernet     | Network scan या sniffing आगे की exploitation सक्षम कर सकता है      |

## GUI application के अंदर संभावित क्रियाओं की जाँच

**Common Dialogs** वे विकल्प हैं जैसे फ़ाइल सेव करना, फ़ाइल खोलना, फ़ॉन्ट चुनना, रंग चुनना... इनमें से अधिकांश आपको full Explorer functionality प्रदान करेंगे. इसका मतलब है कि यदि आप इन विकल्पों तक पहुँच सकते हैं तो आप Explorer functionalities तक पहुँच पाएंगे:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

आपको जाँचना चाहिए कि क्या आप कर सकते हैं:

- फ़ाइलें संशोधित या नई फ़ाइलें बनाना
- Create symbolic links
- प्रतिबंधित क्षेत्रों तक पहुँच प्राप्त करना
- अन्य apps निष्पादित करना

### कमांड निष्पादन

शायद `Open with` विकल्प का उपयोग करके आप किसी तरह का shell खोल/execute कर सकते हैं।

#### Windows

For example _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ find more binaries that can be used to execute commands (and perform unexpected actions) here: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ More here: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### पथ प्रतिबंधों को बायपास करना

- **Environment variables**: बहुत से environment variables ऐसे होते हैं जो किसी पथ की ओर इशारा करते हैं
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Paths to connect to shared folders. You should try to connect to the C$ of the local machine ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: Use *Open/Save/Print-to-file* dialogs as Explorer-lite. Try `*.*` / `*.exe` in the filename field, right-click folders for **Open in new window**, and use **Properties → Open file location** to expand navigation.
- **Create execution paths from dialogs**: एक नई फ़ाइल बनाकर उसे `.CMD` या `.BAT` में रीनाम करें, या `%WINDIR%\System32` की ओर पॉइंट करने वाला शॉर्टकट बनाएं (या किसी specific binary जैसे `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: यदि आप `cmd.exe` तक ब्राउज़ कर सकते हैं, तो किसी भी फ़ाइल को उस पर **drag-and-drop** करके प्रॉम्प्ट लॉन्च करने की कोशिश करें. अगर Task Manager पहुँचा जा सकता है (`CTRL+SHIFT+ESC`), तो **Run new task** का उपयोग करें.
- **Task Scheduler bypass**: यदि interactive shells ब्लॉक हैं पर scheduling अनुमति है, तो `cmd.exe` चलाने के लिए एक task बनाएं (GUI `taskschd.msc` या `schtasks.exe`).
- **Weak allowlists**: यदि execution **filename/extension** द्वारा अनुमति है तो अपने payload का नाम एक अनुमति प्राप्त नाम में बदल दें. यदि अनुमति **directory** द्वारा है, तो payload को एक अनुमत program फ़ोल्डर में कॉपी करें और वहाँ से चलाएँ.
- **Find writable staging paths**: `%TEMP%` से शुरू करें और Sysinternals AccessChk से writable फ़ोल्डरों का enumeration करें.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **अगला कदम**: यदि आप shell प्राप्त कर लेते हैं, तो Windows LPE checklist पर pivot करें:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Download Your Binaries

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### ब्राउज़र से filesystem तक पहुँच

| PATH                | PATH              | PATH               | PATH                |
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
- Toggle Keys – NUMLOCK को 5 सेकंड तक दबा कर रखें
- Filter Keys – दाहिना SHIFT 12 सेकंड तक दबाकर रखें
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Show Desktop
- WINDOWS+E – Launch Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – नए Windows वर्ज़न पर Splash screen
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Internet Explorer में full screen टॉगल करें
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### स्वाइप्स

- बाएँ किनारे से दाएँ की ओर स्वाइप करें ताकि सभी खुली हुई Windows दिखाई दें, KIOSK app मिनिमाइज़ होगा और आप पूरे OS तक सीधे पहुँच पाएँगे;
- दाएँ किनारे से बाएँ की ओर स्वाइप करके Action Center खोलें, KIOSK app मिनिमाइज़ होगा और आप पूरे OS तक सीधे पहुँच पाएँगे;
- शीर्ष किनारे से अंदर की ओर स्वाइप करने पर उस app के लिए title bar दिखाई देगा जो full screen में खुला है;
- निचले हिस्से से ऊपर की ओर स्वाइप करने पर full screen app में taskbar दिखेगा।

### Internet Explorer ट्रिक्स

#### 'Image Toolbar'

यह एक toolbar है जो किसी image पर क्लिक करने पर ऊपर-बाएँ कोने में दिखाई देता है। आप Save, Print, Mailto, Explorer में "My Pictures" खोल सकेंगे। Kiosk को Internet Explorer उपयोग में होना चाहिए।

#### Shell Protocol

Explorer view प्राप्त करने के लिए इन URLs को टाइप करें:

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

अधिक जानकारी के लिए इस पेज को देखें: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browser ट्रिक्स

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript का उपयोग करके एक common dialog बनाकर file explorer तक पहुँच बनाइए: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### इशारे और बटन

- चार (या पाँच) उँगलियों से ऊपर की ओर स्वाइप / Home बटन पर डबल-टैप: मल्टीटास्क view देखने और App बदलने के लिए
- चार या पाँच उँगलियों से किसी एक दिशा में स्वाइप: अगले/पिछले App में बदलने के लिए
- पाँच उँगलियों से स्क्रीन को पिंच करना / Home बटन दबाना / निचले हिस्से से एक उँगली से तेज़ी से ऊपर की ओर स्वाइप करना: Home तक पहुँचने के लिए
- निचले हिस्से से एक उँगली से सिर्फ 1-2 इंच धीमे स्वाइप करने पर: Dock दिखाई देगा
- डिस्प्ले के ऊपर से 1 उँगली से नीचे की ओर स्वाइप: नोटिफिकेशन्स देखने के लिए
- स्क्रीन के ऊपर-दाएँ कोने से 1 उँगली से नीचे की ओर स्वाइप: iPad Pro का control centre देखने के लिए
- स्क्रीन के बाएँ हिस्से से 1 उँगली से 1-2 इंच स्वाइप: Today view देखने के लिए
- बीच से दाएँ या बाएँ तेज़ी से 1 उँगली स्वाइप करने पर: अगले/पिछले App में बदलने के लिए
- iPad के upper-right कोने पर On/**Off**/Sleep बटन दबाकर रखें + Slide to **power off** slider को पूरा दाएँ करें: बंद करने के लिए
- iPad के upper-right पर On/**Off**/Sleep बटन और Home बटन को कुछ सेकंड के लिए दबाकर रखें: हार्ड पावर ऑफ करने के लिए
- iPad के upper-right पर On/**Off**/Sleep बटन और Home बटन को तुरंत जल्दी से दबाएँ: स्क्रीनशॉट लेने के लिए जो डिस्प्ले के निचले बाएँ कोने में पॉपअप होगा। दोनों बटनों को कुछ सेकंड के लिए दबाकर रखने पर हार्ड पावर ऑफ हो जाएगा।

### शॉर्टकट्स

आपके पास iPad कीबोर्ड या USB कीबोर्ड एडैप्टर होना चाहिए। केवल वे शॉर्टकट जिन्हें application से बाहर निकलने में मदद मिल सकेगी यहाँ दिखाए गए हैं।

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

#### सिस्टम शॉर्टकट्स

ये शॉर्टकट्स visual settings और sound settings के लिए हैं, iPad के उपयोग के अनुसार।

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | स्क्रीन को Dim करना                                                            |
| F2       | स्क्रीन को Brighten करना                                                       |
| F7       | पिछला गाना                                                                     |
| F8       | Play/pause                                                                     |
| F9       | अगला गाना                                                                      |
| F10      | Mute                                                                           |
| F11      | आवाज़ कम करना                                                                  |
| F12      | आवाज़ बढ़ाना                                                                   |
| ⌘ Space  | उपलब्ध भाषाओं की सूची दिखाएँ; किसी एक को चुनने के लिए फिर से space बार दबाएँ। |

#### iPad नेविगेशन

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Home पर जाएँ                                            |
| ⌘⇧H (Command-Shift-H)                              | Home पर जाएँ                                            |
| ⌘ (Space)                                          | Spotlight खोलें                                       |
| ⌘⇥ (Command-Tab)                                   | आख़िरी दस प्रयुक्त apps की सूची                        |
| ⌘\~                                                | पिछला App खोलें                                        |
| ⌘⇧3 (Command-Shift-3)                              | स्क्रीनशॉट (निचले बाएँ में hover करता है ताकि save या action हो सके) |
| ⌘⇧4                                                | स्क्रीनशॉट लें और इसे editor में खोलें                  |
| Press and hold ⌘                                   | App के लिए उपलब्ध शॉर्टकट्स की सूची                     |
| ⌘⌥D (Command-Option/Alt-D)                         | Dock लाया जाता है                                      |
| ^⌥H (Control-Option-H)                             | Home बटन                                              |
| ^⌥H H (Control-Option-H-H)                         | Multitask bar दिखाएँ                                   |
| ^⌥I (Control-Option-i)                             | Item chooser                                           |
| Escape                                             | Back बटन                                              |
| → (Right arrow)                                    | अगला आइटम                                              |
| ← (Left arrow)                                     | पिछला आइटम                                             |
| ↑↓ (Up arrow, Down arrow)                          | चुने हुए आइटम को एक साथ टैप करना                       |
| ⌥ ↓ (Option-Down arrow)                            | नीचे स्क्रॉल करें                                      |
| ⌥↑ (Option-Up arrow)                               | ऊपर स्क्रॉल करें                                       |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | बाएँ या दाएँ स्क्रॉल करें                               |
| ^⌥S (Control-Option-S)                             | VoiceOver स्पीच चालू/बंद करें                          |
| ⌘⇧⇥ (Command-Shift-Tab)                            | पिछले app पर स्विच करें                                |
| ⌘⇥ (Command-Tab)                                   | मूल app पर वापस स्विच करें                             |
| ←+→, then Option + ← or Option+→                   | Dock में नेविगेट करें                                  |

#### Safari शॉर्टकट्स

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Location खोलें                                   |
| ⌘T                      | नया टैब खोलें                                   |
| ⌘W                      | वर्तमान टैब बंद करें                             |
| ⌘R                      | वर्तमान टैब रिफ्रेश करें                         |
| ⌘.                      | वर्तमान टैब का लोड रोकें                         |
| ^⇥                      | अगले टैब पर जाएँ                                 |
| ^⇧⇥ (Control-Shift-Tab) | पिछले टैब पर जाएँ                                |
| ⌘L                      | टेक्स्ट इनपुट/URL फ़ील्ड का चयन करें ताकि आप इसे संशोधित कर सकें |
| ⌘⇧T (Command-Shift-T)   | आख़िरी बंद किया गया टैब खोलें (इसे कई बार उपयोग किया जा सकता है) |
| ⌘\[                     | ब्राउज़िंग इतिहास में एक पृष्ठ पीछे जाएँ          |
| ⌘]                      | ब्राउज़िंग इतिहास में एक पृष्ठ आगे जाएँ           |
| ⌘⇧R                     | Reader Mode सक्रिय करें                           |

#### Mail शॉर्टकट्स

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Location खोलें               |
| ⌘T                         | नया टैब खोलें               |
| ⌘W                         | वर्तमान टैब बंद करें        |
| ⌘R                         | वर्तमान टैब रिफ्रेश करें    |
| ⌘.                         | वर्तमान टैब का लोड रोकें     |
| ⌘⌥F (Command-Option/Alt-F) | अपने mailbox में खोजें       |

## संदर्भ

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
