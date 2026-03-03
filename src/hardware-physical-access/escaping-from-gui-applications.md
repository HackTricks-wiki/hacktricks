# KIOSKs से बाहर निकलना

{{#include ../banners/hacktricks-training.md}}

---

## भौतिक डिवाइस की जाँच

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| पावर बटन     | डिवाइस को बंद करके फिर चालू करने से स्टार्ट स्क्रीन प्रकट हो सकती है |
| पावर केबल    | पावर को थोड़े समय के लिए काटने पर डिवाइस रिबूट होता है या नहीं जाँचें |
| USB पोर्ट्स  | अधिक शॉर्टकट वाले भौतिक कीबोर्ड को कनेक्ट करें                    |
| Ethernet     | नेटवर्क स्कैन या स्निफिंग आगे के exploitation को सक्षम कर सकती है  |

## GUI application के अंदर संभावित कार्यों की जाँच

**Common Dialogs** वे विकल्प होते हैं जैसे **फाइल सेव करना**, **फाइल खोलना**, फ़ॉन्ट चुनना, रंग चुनना... इनमें से अधिकांश **Explorer functionality** प्रदान करते हैं। इसका मतलब है कि अगर आप इन विकल्पों तक पहुँच सकते हैं तो आप Explorer functionalities का उपयोग कर पाएंगे:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

आपको जाँचना चाहिए कि क्या आप कर सकते हैं:

- फ़ाइलों में संशोधन करना या नई फ़ाइलें बनाना
- symbolic links बनाना
- restricted क्षेत्रों तक पहुँच प्राप्त करना
- अन्य apps को execute करना

### Command Execution

शायद **using a `Open with`** option\*\* का उपयोग करके आप किसी प्रकार का shell खोल/निष्पादित कर सकते हैं।

#### Windows

उदाहरण के लिए _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ अधिक ऐसे binaries देखें जिन्हें कमांड execute करने (और अनपेक्षित actions करने) के लिए उपयोग किया जा सकता है यहाँ: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ और जानकारी यहाँ: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### पाथ प्रतिबंधों को बायपास करना

- **Environment variables**: बहुत सारे environment variables ऐसे होते हैं जो किसी पाथ की ओर इशारा करते हैं
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: साझा फोल्डरों से कनेक्ट करने के पथ। आपको लोकल मशीन के C$ से कनेक्ट करने की कोशिश करनी चाहिए ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: *Open/Save/Print-to-file* dialogs को Explorer-lite की तरह उपयोग करें। filename field में `*.*` / `*.exe` आज़माएँ, फोल्डरों पर राइट-क्लिक कर **Open in new window** चुनें, और नेविगेशन बढ़ाने के लिए **Properties → Open file location** का उपयोग करें।
- **Create execution paths from dialogs**: एक नई फ़ाइल बनाएं और इसे `.CMD` या `.BAT` में rename करें, या `%WINDIR%\System32` (या किसी विशिष्ट binary जैसे `%WINDIR%\System32\cmd.exe`) की ओर इशारा करता एक shortcut बनाएं।
- **Shell launch pivots**: अगर आप `cmd.exe` तक ब्राउज़ कर सकते हैं, तो किसी भी फ़ाइल को उस पर **drag-and-drop** कर के एक prompt लॉन्च करने की कोशिश करें। अगर Task Manager उपलब्ध है (`CTRL+SHIFT+ESC`), तो **Run new task** का उपयोग करें।
- **Task Scheduler bypass**: अगर interactive shells ब्लॉक हैं लेकिन scheduling की अनुमति है, तो `cmd.exe` चलाने के लिए एक task बनाएं (GUI `taskschd.msc` या `schtasks.exe`)।
- **Weak allowlists**: अगर execution केवल **filename/extension** द्वारा अनुमति है, तो अपने payload का नाम किसी अनुमति प्राप्त नाम पर बदल दें। अगर अनुमति केवल **directory** द्वारा है, तो payload को अनुमति प्राप्त program फ़ोल्डर में कॉपी कर वहाँ से चलाएँ।
- **Find writable staging paths**: `%TEMP%` से शुरू करें और Sysinternals AccessChk के साथ writable फ़ोल्डरों का enumeration करें।
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **अगला कदम**: यदि आपको shell मिल जाता है, तो Windows LPE checklist पर pivot करें:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### अपने बाइनरी डाउनलोड करें

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### ब्राउज़र से filesystem एक्सेस करना

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### शॉर्टकट

- Sticky Keys – SHIFT को 5 बार दबाएँ
- Mouse Keys – SHIFT+ALT+NUMLOCK दबाएँ
- High Contrast – SHIFT+ALT+PRINTSCN दबाएँ
- Toggle Keys – NUMLOCK को 5 सेकंड तक दबाकर रखें
- Filter Keys – दाहिने SHIFT को 12 सेकंड तक दबाकर रखें
- WINDOWS+F1 – Windows Search
- WINDOWS+D – डेस्कटॉप दिखाएँ
- WINDOWS+E – Windows Explorer लॉन्च करें
- WINDOWS+R – Run खोलें
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – नए Windows वर्ज़नों पर स्प्लैश स्क्रीन
- F1 – Help  F3 – Search
- F6 – Address Bar
- F11 – Internet Explorer में फुल स्क्रीन टॉगल करें
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save  CTRL+N – New RDP / Citrix

### स्वाइप्स

- बाएँ किनारे से दाएँ की ओर स्वाइप करने पर सभी खुले Windows दिखाई देंगे, KIOSK app मिनिमाइज़ होगा और आप सीधे पूरे OS तक पहुँच पाएंगे;
- दाएँ किनारे से बाएँ की ओर स्वाइप करने पर Action Center खुल जाएगा, KIOSK app मिनिमाइज़ होगा और आप सीधे पूरे OS तक पहुँच पाएंगे;
- ऊपर की किनारी से अंदर की ओर स्वाइप करने पर पूर्ण स्क्रीन में खोले गए किसी ऐप की title bar दिखाई देगी;
- नीचे से ऊपर की ओर स्वाइप करने पर पूर्ण स्क्रीन ऐप में taskbar दिखेगा।

### Internet Explorer ट्रिक्स

#### 'Image Toolbar'

यह एक toolbar है जो इमेज पर क्लिक करने पर ऊपर-बाएँ तरफ प्रकट होती है। आप Save, Print, Mailto, Explorer में "My Pictures" खोलने में सक्षम होंगे। Kiosk को Internet Explorer उपयोग करना चाहिए।

#### Shell Protocol

Explorer view प्राप्त करने के लिए ये URLs टाइप करें:

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

### फाइल एक्सटेंशन्स दिखाएँ

अधिक जानकारी के लिए इस पेज को देखें: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## ब्राउज़र ट्रिक्स

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript का उपयोग करके एक common dialog बनाएं और file explorer तक पहुँचें: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### जेस्चर और बटन

- चार (या पाँच) उंगलियों से ऊपर की ओर स्वाइप करें / Home बटन पर डबल-टैप करें: मल्टीटास्क व्यू देखने और ऐप बदलने के लिए
- चार या पाँच उंगलियों से किसी एक दिशा में स्वाइप करें: अगले/पिछले ऐप पर जाने के लिए
- पाँच उंगलियों से स्क्रीन को चिमोटें / Home बटन दबाएँ / नीचे से ऊपर की ओर एक फिंगर से तेज़ी से स्वाइप करें: Home तक पहुँचने के लिए
- नीचे की ओर से सिर्फ़ 1–2 इंच (धीरे) एक उंगली से स्वाइप करें: Dock दिखाई देगा
- एक उंगली से डिस्प्ले के ऊपर की ओर स्वाइप करें: नोटिफिकेशन देखने के लिए
- ऊपर-दाएँ कोने से एक उंगली से नीचे की ओर स्वाइप करें: iPad Pro का control centre देखने के लिए
- एक उंगली को स्क्रीन के बाएँ से 1–2 इंच स्वाइप करें: Today view देखने के लिए
- स्क्रीन के केंद्र से दाएँ या बाएँ तेज़ी से एक उंगली से स्वाइप करें: अगले/पिछले ऐप में जाने के लिए
- On/**Off**/Sleep बटन को ऊपर-दाएँ कोने में दबाकर रखें और **iPad +** पर Slide to **power off** स्लाइडर को दाईं ओर ले जाएँ: पावर बंद करने के लिए
- On/**Off**/Sleep बटन और Home बटन को कुछ सेकंड के लिए दबाकर रखें: हार्ड पावर ऑफ के लिए
- On/**Off**/Sleep बटन और Home बटन को जल्दी से दबाएँ: स्क्रीनशॉट लेने के लिए जो डिस्प्ले के निचले बाएँ हिस्से में प्रकट होगा। दोनों बटन को बहुत थोड़ी देर के लिए एक साथ दबाने पर हार्ड पावर ऑफ हो सकता है।

### शॉर्टकट

आपके पास iPad कीबोर्ड या USB कीबोर्ड एडॉप्टर होना चाहिए। यहाँ केवल वे शॉर्टकट दिखाए गए हैं जो ऐप से बाहर निकलने में मदद कर सकते हैं।

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

#### सिस्टम शॉर्टकट

ये शॉर्टकट visual सेटिंग्स और sound सेटिंग्स के लिए हैं, उपयोग के अनुसार।

| Shortcut | Action                                                                 |
| -------- | ---------------------------------------------------------------------- |
| F1       | स्क्रीन मंद करें                                                       |
| F2       | स्क्रीन तेज करें                                                       |
| F7       | पिछला गीत                                                             |
| F8       | प्ले/पॉज़                                                               |
| F9       | अगले गीत पर जाएँ                                                       |
| F10      | म्यूट                                                                  |
| F11      | वॉल्यूम घटाएँ                                                           |
| F12      | वॉल्यूम बढ़ाएँ                                                          |
| ⌘ Space  | उपलब्ध भाषाओं की सूची दिखाएँ; चुनने के लिए स्पेस बार फिर दबाएँ।        |

#### iPad नेविगेशन

| Shortcut                                           | Action                                                    |
| -------------------------------------------------- | --------------------------------------------------------- |
| ⌘H                                                 | Home पर जाएँ                                              |
| ⌘⇧H (Command-Shift-H)                              | Home पर जाएँ                                              |
| ⌘ (Space)                                          | Spotlight खोलें                                          |
| ⌘⇥ (Command-Tab)                                   | आखिरी दस उपयोग किए गए ऐप्स सूचीबद्ध करें                 |
| ⌘\~                                                | पिछले ऐप पर जाएँ                                         |
| ⌘⇧3 (Command-Shift-3)                              | स्क्रीनशॉट (नीचे बाएँ में प्रकट होता है, सहेजने/कार्रवाई के लिए) |
| ⌘⇧4                                                | स्क्रीनशॉट ले और एडिटर में खोलें                         |
| Press and hold ⌘                                   | ऐप के लिए उपलब्ध शॉर्टकट्स की सूची दिखाएँ                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Dock लाएँ                                                 |
| ^⌥H (Control-Option-H)                             | Home बटन                                                  |
| ^⌥H H (Control-Option-H-H)                         | मल्टीटास्क बार दिखाएँ                                     |
| ^⌥I (Control-Option-i)                             | आइटम चुनने वाला खोलें                                    |
| Escape                                             | बैक बटन                                                   |
| → (Right arrow)                                    | अगला आइटम                                                |
| ← (Left arrow)                                     | पिछला आइटम                                               |
| ↑↓ (Up arrow, Down arrow)                          | चयनित आइटम पर एक साथ टैप करें                           |
| ⌥ ↓ (Option-Down arrow)                            | नीचे स्क्रोल करें                                         |
| ⌥↑ (Option-Up arrow)                               | ऊपर स्क्रोल करें                                          |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | बाएँ या दाएँ स्क्रोल करें                                 |
| ^⌥S (Control-Option-S)                             | VoiceOver की आवाज़ चालू/बंद करें                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | पिछले ऐप पर स्विच करें                                   |
| ⌘⇥ (Command-Tab)                                   | मूल ऐप पर वापस स्विच करें                                |
| ←+→, then Option + ← or Option+→                   | Dock के माध्यम से नेविगेट करें                            |

#### Safari शॉर्टकट्स

| Shortcut                | Action                                              |
| ----------------------- | --------------------------------------------------- |
| ⌘L (Command-L)          | Location खोलें                                      |
| ⌘T                      | नया टैब खोलें                                      |
| ⌘W                      | वर्तमान टैब बंद करें                                |
| ⌘R                      | वर्तमान टैब रिफ्रेश करें                            |
| ⌘.                      | वर्तमान टैब का लोड रोकें                            |
| ^⇥                      | अगले टैब पर जाएँ                                    |
| ^⇧⇥ (Control-Shift-Tab) | पिछले टैब पर जाएँ                                   |
| ⌘L                      | टेक्स्ट इनपुट/URL फील्ड को चुनें ताकि आप उसे बदल सकें |
| ⌘⇧T (Command-Shift-T)   | आखिरी बंद किया गया टैब खोलें (कई बार उपयोग कर सकते हैं) |
| ⌘\[                     | ब्राउज़िंग इतिहास में एक पेज पीछे जाएँ               |
| ⌘]                      | ब्राउज़िंग इतिहास में एक पेज आगे जाएँ                |
| ⌘⇧R                     | Reader Mode सक्रिय करें                              |

#### Mail शॉर्टकट्स

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Location खोलें              |
| ⌘T                         | नया टैब खोलें               |
| ⌘W                         | वर्तमान टैब बंद करें        |
| ⌘R                         | वर्तमान टैब रिफ्रेश करें    |
| ⌘.                         | वर्तमान टैब का लोड रोकें     |
| ⌘⌥F (Command-Option/Alt-F) | अपने mailbox में खोज करें    |

## संदर्भ

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
