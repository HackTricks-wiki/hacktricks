{{#include ../../banners/hacktricks-training.md}}

# Angalia hatua zinazowezekana ndani ya programu ya GUI

**Mazungumzo ya Kawaida** ni zile chaguzi za **kuhifadhi faili**, **kufungua faili**, kuchagua fonti, rangi... Mengi yao yatatoa **ufunctionality kamili ya Explorer**. Hii inamaanisha kwamba utaweza kufikia functionalities za Explorer ikiwa utaweza kufikia chaguzi hizi:

- Funga/Funga kama
- Fungua/Fungua na
- Chapisha
- Hamisha/Pokea
- Tafuta
- Scan

Unapaswa kuangalia ikiwa unaweza:

- Kubadilisha au kuunda faili mpya
- Kuunda viungo vya alama
- Kupata ufikiaji wa maeneo yaliyopigwa marufuku
- Kutekeleza programu nyingine

## Utekelezaji wa Amri

Labda **ukitumia chaguo la `Fungua na`** unaweza kufungua/kutekeleza aina fulani ya shell.

### Windows

Kwa mfano _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pata zaidi ya binaries ambazo zinaweza kutumika kutekeleza amri (na kufanya vitendo visivyotarajiwa) hapa: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX \_\_

_bash, sh, zsh..._ Zaidi hapa: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Kupita vizuizi vya njia

- **Mabadiliko ya mazingira**: Kuna mabadiliko mengi ya mazingira yanayoelekeza kwenye njia fulani
- **Protokali nyingine**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Viungo vya alama**
- **Mifano**: CTRL+N (fungua kikao kipya), CTRL+R (Tekeleza Amri), CTRL+SHIFT+ESC (Meneja wa Kazi), Windows+E (fungua explorer), CTRL-B, CTRL-I (Mipendekezo), CTRL-H (Historia), CTRL-L, CTRL-O (Faili/Fungua Mazungumzo), CTRL-P (Chapisha Mazungumzo), CTRL-S (Hifadhi Kama)
- Menyu ya Usimamizi iliyofichwa: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **Njia za UNC**: Njia za kuungana na folda zilizoshirikiwa. Unapaswa kujaribu kuungana na C$ ya mashine ya ndani ("\\\127.0.0.1\c$\Windows\System32")
- **Njia zaidi za UNC:**

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

## Pakua Binaries Zako

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Mhariri wa rejista: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Kupata mfumo wa faili kutoka kwa kivinjari

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Mifano

- Fungua funguo – Bonyeza SHIFT mara 5
- Funguo za Panya – SHIFT+ALT+NUMLOCK
- Mwangaza Mkali – SHIFT+ALT+PRINTSCN
- Funguo za Kubadili – Shikilia NUMLOCK kwa sekunde 5
- Funguo za Filter – Shikilia SHIFT ya kulia kwa sekunde 12
- WINDOWS+F1 – Utafutaji wa Windows
- WINDOWS+D – Onyesha Desktop
- WINDOWS+E – Anzisha Windows Explorer
- WINDOWS+R – Kimbia
- WINDOWS+U – Kituo cha Urahisi wa Ufikiaji
- WINDOWS+F – Tafuta
- SHIFT+F10 – Menyu ya Muktadha
- CTRL+SHIFT+ESC – Meneja wa Kazi
- CTRL+ALT+DEL – Skrini ya Splash kwenye toleo jipya la Windows
- F1 – Msaada F3 – Tafuta
- F6 – Bar ya Anwani
- F11 – Badilisha skrini kamili ndani ya Internet Explorer
- CTRL+H – Historia ya Internet Explorer
- CTRL+T – Internet Explorer – Kichupo Kipya
- CTRL+N – Internet Explorer – Ukurasa Mpya
- CTRL+O – Fungua Faili
- CTRL+S – Hifadhi CTRL+N – RDP Mpya / Citrix

## Mswipe

- Swipe kutoka upande wa kushoto kwenda kulia ili kuona Windows zote zilizo wazi, kupunguza programu ya KIOSK na kufikia mfumo mzima wa uendeshaji moja kwa moja;
- Swipe kutoka upande wa kulia kwenda kushoto kufungua Kituo cha Hatua, kupunguza programu ya KIOSK na kufikia mfumo mzima wa uendeshaji moja kwa moja;
- Swipe kutoka kwenye kingo ya juu ili kufanya bar ya kichwa ionekane kwa programu iliyofunguliwa kwa hali ya skrini kamili;
- Swipe juu kutoka chini kuonyesha upau wa kazi katika programu ya skrini kamili.

## Hila za Internet Explorer

### 'Kichombo cha Picha'

Ni kichombo kinachotokea juu-kushoto ya picha wakati kinapobonyezwa. Utaweza Kuhifadhi, Chapisha, Mailto, Fungua "Picha Zangu" katika Explorer. Kiosk inahitaji kutumia Internet Explorer.

### Protokali ya Shell

Andika hizi URLs ili kupata mtazamo wa Explorer:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Kituo cha Kudhibiti
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Kompyuta Yangu
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mahali Yangu ya Mtandao
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Onyesha Nyongeza za Faili

Angalia ukurasa huu kwa maelezo zaidi: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Hila za Kivinjari

Backup iKat toleo:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Unda mazungumzo ya kawaida kwa kutumia JavaScript na upate explorer ya faili: `document.write('<input/type=file>')`
Chanzo: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestures na vifungo

- Swipe juu na vidole vinne (au vitano) / Bonyeza mara mbili kitufe cha Nyumbani: Ili kuona mtazamo wa multitask na kubadilisha Programu

- Swipe kwa njia moja au nyingine na vidole vinne au vitano: Ili kubadilisha kwenda kwenye Programu inayofuata/ya mwisho

- Pinch skrini na vidole vitano / Gusa kitufe cha Nyumbani / Swipe juu na kidole 1 kutoka chini ya skrini kwa haraka: Ili kufikia Nyumbani

- Swipe kidole 1 kutoka chini ya skrini inchi 1-2 (polepole): Dock itaonekana

- Swipe chini kutoka juu ya onyesho kwa kidole 1: Ili kuona arifa zako

- Swipe chini kwa kidole 1 kwenye kona ya juu-kulia ya skrini: Ili kuona kituo cha kudhibiti cha iPad Pro

- Swipe kidole 1 kutoka kushoto mwa skrini inchi 1-2: Ili kuona mtazamo wa Leo

- Swipe haraka kidole 1 kutoka katikati ya skrini kwenda kulia au kushoto: Ili kubadilisha kwenda kwenye Programu inayofuata/ya mwisho

- Bonyeza na shikilia kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad +** Hamisha Slide ili **kuzimisha** slider yote kwenda kulia: Ili kuzima

- Bonyeza kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad na kitufe cha Nyumbani kwa sekunde chache**: Ili kulazimisha kuzima kwa nguvu

- Bonyeza kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad na kitufe cha Nyumbani haraka**: Ili kuchukua picha ya skrini ambayo itatokea chini kushoto ya onyesho. Bonyeza vitufe vyote kwa wakati mmoja kwa muda mfupi kana kwamba unavyoshikilia kwa sekunde chache kuzima kwa nguvu kutafanyika.

## Mifano

Unapaswa kuwa na kibodi ya iPad au adapta ya kibodi ya USB. Mifano pekee ambazo zinaweza kusaidia kutoroka kutoka kwa programu zitakuwa hapa.

| Key | Jina         |
| --- | ------------ |
| ⌘   | Amri        |
| ⌥   | Chaguo (Alt) |
| ⇧   | Shift        |
| ↩   | Kurudi       |
| ⇥   | Tab          |
| ^   | Udhibiti      |
| ←   | Arrow ya Kushoto   |
| →   | Arrow ya Kulia  |
| ↑   | Arrow ya Juu     |
| ↓   | Arrow ya Chini   |

### Mifano ya Mfumo

Mifano hii ni kwa mipangilio ya kuona na mipangilio ya sauti, kulingana na matumizi ya iPad.

| Mifano | Kitendo                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Punguza Sscreen                                                                |
| F2       | Pandisha skrini                                                                |
| F7       | Rudi wimbo mmoja                                                              |
| F8       | Cheza/Simamisha                                                                |
| F9       | Kosa wimbo                                                                     |
| F10      | Zima                                                                           |
| F11      | Punguza sauti                                                                  |
| F12      | Pandisha sauti                                                                |
| ⌘ Space  | Onyesha orodha ya lugha zinazopatikana; ili kuchagua moja, bonyeza upya nafasi. |

### Usafiri wa iPad

| Mifano                                           | Kitendo                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Nenda Nyumbani                                          |
| ⌘⇧H (Amri-Shift-H)                              | Nenda Nyumbani                                          |
| ⌘ (Space)                                          | Fungua Spotlight                                        |
| ⌘⇥ (Amri-Tab)                                   | Orodha ya programu kumi zilizotumika hivi karibuni     |
| ⌘\~                                                | Nenda kwenye Programu ya mwisho                         |
| ⌘⇧3 (Amri-Shift-3)                              | Picha ya skrini (inashikilia chini kushoto kuhifadhi au kufanya kazi nayo) |
| ⌘⇧4                                                | Picha ya skrini na ifungue kwenye mhariri              |
| Bonyeza na shikilia ⌘                                   | Orodha ya mifano inayopatikana kwa Programu             |
| ⌘⌥D (Amri-Chaguo/Alt-D)                         | Inaleta dock                                            |
| ^⌥H (Udhibiti-Chaguo-H)                             | Kitufe cha Nyumbani                                     |
| ^⌥H H (Udhibiti-Chaguo-H-H)                         | Onyesha upau wa multitask                                |
| ^⌥I (Udhibiti-Chaguo-i)                             | Chaguo la kipengee                                      |
| Escape                                             | Kitufe cha nyuma                                        |
| → (Arrow ya Kulia)                                    | Kipengee kinachofuata                                   |
| ← (Arrow ya Kushoto)                                     | Kipengee kilichopita                                     |
| ↑↓ (Arrow ya Juu, Arrow ya Chini)                          | Bonyeza kwa pamoja kipengee kilichochaguliwa           |
| ⌥ ↓ (Chaguo-Arrow ya Chini)                            | Punguza chini                                           |
| ⌥↑ (Chaguo-Arrow ya Juu)                               | Pandisha juu                                           |
| ⌥← au ⌥→ (Chaguo-Arrow ya Kushoto au Chaguo-Arrow ya Kulia) | Punguza kushoto au kulia                                 |
| ^⌥S (Udhibiti-Chaguo-S)                             | Geuza sauti ya VoiceOver kuwa juu au chini              |
| ⌘⇧⇥ (Amri-Shift-Tab)                            | Badilisha kwenda kwenye programu ya awali              |
| ⌘⇥ (Amri-Tab)                                   | Badilisha kurudi kwenye programu ya awali               |
| ←+→, kisha Chaguo + ← au Chaguo+→                   | Tembea kupitia Dock                                     |

### Mifano ya Safari

| Mifano                | Kitendo                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Amri-L)          | Fungua Mahali                                    |
| ⌘T                      | Fungua kichupo kipya                             |
| ⌘W                      | Funga kichupo cha sasa                           |
| ⌘R                      | Refresh kichupo cha sasa                         |
| ⌘.                      | Simamisha kupakia kichupo cha sasa              |
| ^⇥                      | Badilisha kwenda kwenye kichupo kinachofuata    |
| ^⇧⇥ (Udhibiti-Shift-Tab) | Hamisha kwenda kwenye kichupo kilichopita       |
| ⌘L                      | Chagua uwanja wa kuingiza maandiko/URL ili kuibadilisha |
| ⌘⇧T (Amri-Shift-T)   | Fungua kichupo kilichofungwa mwisho (kinaweza kutumika mara kadhaa) |
| ⌘\[                     | Rudi ukurasa mmoja katika historia yako ya kuvinjari |
| ⌘]                      | Nenda mbele ukurasa mmoja katika historia yako ya kuvinjari |
| ⌘⇧R                     | Aktivisha Modu ya Msomaji                       |

### Mifano ya Barua

| Mifano                   | Kitendo                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Fungua Mahali                |
| ⌘T                         | Fungua kichupo kipya         |
| ⌘W                         | Funga kichupo cha sasa       |
| ⌘R                         | Refresh kichupo cha sasa      |
| ⌘.                         | Simamisha kupakia kichupo cha sasa |
| ⌘⌥F (Amri-Chaguo/Alt-F) | Tafuta kwenye sanduku lako la barua |

# Marejeleo

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../../banners/hacktricks-training.md}}
