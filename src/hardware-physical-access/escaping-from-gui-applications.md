# Kutoroka kutoka KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Angalia kifaa cha kimwili

| Kipengele     | Hatua                                                              |
| --------------| ------------------------------------------------------------------ |
| Kitufe cha nguvu | Kuwasha na kuzima kifaa kunaweza kufichua skrini ya kuanzia    |
| Kebuli ya nguvu  | Angalia ikiwa kifaa kinarejea nyuma wakati nguvu inakatwa kwa muda mfupi |
| Bandari za USB    | Unganisha kibodi ya kimwili yenye njia zaidi                      |
| Ethernet        | Skana ya mtandao au sniffing inaweza kuwezesha unyakuzi zaidi           |

## Angalia hatua zinazowezekana ndani ya programu ya GUI

**Maongezi ya Kawaida** ni zile chaguzi za **kuhifadhi faili**, **kufungua faili**, kuchagua fonti, rangi... Mengi yao yatatoa **ufanyaji kazi wa Explorer kamili**. Hii inamaanisha kwamba utaweza kufikia kazi za Explorer ikiwa utaweza kufikia chaguzi hizi:

- Funga/Funga kama
- Fungua/Fungua na
- Chapisha
- Export/Import
- Tafuta
- Skana

Unapaswa kuangalia ikiwa unaweza:

- Kubadilisha au kuunda faili mpya
- Kuunda viungo vya ishara
- Kupata ufikiaji wa maeneo yaliyopigwa marufuku
- Kutekeleza programu nyingine

### Utekelezaji wa Amri

Labda **ukitumia chaguo la `Fungua na`** unaweza kufungua/kutekeleza aina fulani ya shell.

#### Windows

Kwa mfano _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ pata zaidi ya binaries zinazoweza kutumika kutekeleza amri (na kufanya vitendo visivyotarajiwa) hapa: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Zaidi hapa: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Kupita vizuizi vya njia

- **Mabadiliko ya mazingira**: Kuna mabadiliko mengi ya mazingira yanayoelekeza kwenye njia fulani
- **Protokali nyingine**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Viungo vya ishara**
- **Njia fupi**: CTRL+N (fungua kikao kipya), CTRL+R (Tekeleza Amri), CTRL+SHIFT+ESC (Meneja wa Kazi), Windows+E (fungua explorer), CTRL-B, CTRL-I (Kipenzi), CTRL-H (Historia), CTRL-L, CTRL-O (Faili/Fungua Maongezi), CTRL-P (Chapisha Maongezi), CTRL-S (Hifadhi Kama)
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

### Pakua Binaries Zako

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Mhariri wa rejista: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Kupata mfumo wa faili kutoka kwa kivinjari

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Njia Fupi

- Funguo za Sticky – Bonyeza SHIFT mara 5
- Funguo za Panya – SHIFT+ALT+NUMLOCK
- Mwangaza Mkali – SHIFT+ALT+PRINTSCN
- Funguo za Kubadilisha – Shikilia NUMLOCK kwa sekunde 5
- Funguo za Filter – Shikilia SHIFT ya kulia kwa sekunde 12
- WINDOWS+F1 – Utafutaji wa Windows
- WINDOWS+D – Onyesha Desktop
- WINDOWS+E – Anzisha Windows Explorer
- WINDOWS+R – Kimbia
- WINDOWS+U – Kituo cha Ufikiaji Rahisi
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

### Swipes

- Swipe kutoka upande wa kushoto kwenda kulia kuona Windows zote zilizo wazi, kupunguza programu ya KIOSK na kufikia mfumo mzima wa uendeshaji moja kwa moja;
- Swipe kutoka upande wa kulia kwenda kushoto kufungua Kituo cha Hatua, kupunguza programu ya KIOSK na kufikia mfumo mzima wa uendeshaji moja kwa moja;
- Swipe kutoka kwenye kingo ya juu ili kufanya bar ya kichwa ionekane kwa programu iliyofunguliwa kwa hali ya skrini kamili;
- Swipe juu kutoka chini kuonyesha bar ya kazi katika programu ya skrini kamili.

### Hila za Internet Explorer

#### 'Image Toolbar'

Ni bar ya zana inayojitokeza juu-kushoto ya picha wakati inabonyezwa. Utaweza Kuhifadhi, Chapisha, Mailto, Fungua "Picha Zangu" katika Explorer. Kiosk inahitaji kutumia Internet Explorer.

#### Protokali ya Shell

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
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mahali Pangu ya Mtandao
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Onyesha Nyongeza za Faili

Angalia ukurasa huu kwa maelezo zaidi: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Hila za Kivinjari

Backup iKat toleo:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Unda mazungumzo ya kawaida kwa kutumia JavaScript na upate explorer ya faili: `document.write('<input/type=file>')`\
Chanzo: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures na vitufe

- Swipe juu kwa vidole vinne (au vitano) / Bonyeza mara mbili kitufe cha Nyumbani: Ili kuona mtazamo wa multitask na kubadilisha Programu
- Swipe kwa njia moja au nyingine kwa vidole vinne au vitano: Ili kubadilisha kwenda kwenye Programu inayofuata/ya mwisho
- Pinch skrini kwa vidole vitano / Gusa kitufe cha Nyumbani / Swipe juu kwa kidole 1 kutoka chini ya skrini kwa haraka: Ili kufikia Nyumbani
- Swipe kidole kimoja kutoka chini ya skrini inchi 1-2 (polepole): Dock itaonekana
- Swipe chini kutoka juu ya skrini kwa kidole 1: Ili kuona arifa zako
- Swipe chini kwa kidole 1 kwenye kona ya juu-kulia ya skrini: Ili kuona kituo cha kudhibiti cha iPad Pro
- Swipe kidole 1 kutoka kushoto mwa skrini inchi 1-2: Ili kuona mtazamo wa Leo
- Swipe haraka kidole 1 kutoka katikati ya skrini kwenda kulia au kushoto: Ili kubadilisha kwenda kwenye Programu inayofuata/ya mwisho
- Bonyeza na shikilia kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad +** Hamisha Slide hadi **kuwasha off** slider yote kwenda kulia: Ili kuwasha off
- Bonyeza kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad na kitufe cha Nyumbani kwa sekunde chache**: Ili kulazimisha kuwasha off kwa nguvu
- Bonyeza kitufe cha On/**Off**/Sleep kwenye kona ya juu-kulia ya **iPad na kitufe cha Nyumbani haraka**: Ili kuchukua picha ya skrini ambayo itajitokeza chini kushoto ya skrini. Bonyeza vitufe vyote kwa wakati mmoja kwa muda mfupi kana kwamba unavyoshikilia kwa sekunde chache kuwasha off kwa nguvu kutafanyika.

### Njia Fupi

Unapaswa kuwa na kibodi ya iPad au adapta ya kibodi ya USB. Njia fupi pekee ambazo zinaweza kusaidia kutoroka kutoka kwa programu zitaonyeshwa hapa.

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

#### Njia fupi za Mfumo

Njia fupi hizi ni za mipangilio ya kuona na mipangilio ya sauti, kulingana na matumizi ya iPad.

| Njia Fupi | Hatua                                                                         |
| --------- | ------------------------------------------------------------------------------ |
| F1        | Punguza Mwanga                                                                |
| F2        | Pandisha mwanga                                                               |
| F7        | Rudi wimbo mmoja                                                              |
| F8        | Cheza/Simamisha                                                               |
| F9        | Kataa wimbo                                                                    |
| F10       | Zima                                                                           |
| F11       | Punguza sauti                                                                  |
| F12       | Pandisha sauti                                                                |
| ⌘ Space   | Onyesha orodha ya lugha zinazopatikana; ili kuchagua moja, bonyeza upya nafasi. |

#### Usafiri wa iPad

| Njia Fupi                                           | Hatua                                                  |
| --------------------------------------------------- | ----------------------------------------------------- |
| ⌘H                                                 | Nenda Nyumbani                                         |
| ⌘⇧H (Amri-Shift-H)                                 | Nenda Nyumbani                                         |
| ⌘ (Space)                                         | Fungua Spotlight                                       |
| ⌘⇥ (Amri-Tab)                                     | Orodha ya programu kumi zilizotumika hivi karibuni   |
| ⌘\~                                               | Nenda kwenye Programu ya mwisho                        |
| ⌘⇧3 (Amri-Shift-3)                                | Picha ya skrini (inabaki chini kushoto kuhifadhi au kufanya nayo) |
| ⌘⇧4                                              | Picha ya skrini na ifungue kwenye mhariri            |
| Bonyeza na shikilia ⌘                              | Orodha ya njia fupi zinazopatikana kwa Programu       |
| ⌘⌥D (Amri-Chaguo/Alt-D)                           | Inaleta dock                                           |
| ^⌥H (Udhibiti-Chaguo-H)                            | Kitufe cha Nyumbani                                    |
| ^⌥H H (Udhibiti-Chaguo-H-H)                        | Onyesha bar ya multitask                                |
| ^⌥I (Udhibiti-Chaguo-i)                            | Chaguo la kipengee                                     |
| Escape                                             | Kitufe cha nyuma                                       |
| → (Arrow ya Kulia)                                 | Kipengee kinachofuata                                  |
| ← (Arrow ya Kushoto)                               | Kipengee kilichopita                                    |
| ↑↓ (Arrow ya Juu, Arrow ya Chini)                 | Bonyeza kwa pamoja kipengee kilichochaguliwa          |
| ⌥ ↓ (Chaguo-Arrow ya Chini)                        | Punguza chini                                           |
| ⌥↑ (Chaguo-Arrow ya Juu)                           | Pandisha juu                                           |
| ⌥← au ⌥→ (Chaguo-Arrow ya Kushoto au Chaguo-Arrow ya Kulia) | Punguza kushoto au kulia                                |
| ^⌥S (Udhibiti-Chaguo-S)                            | Washa au zima sauti ya VoiceOver                       |
| ⌘⇧⇥ (Amri-Shift-Tab)                              | Badilisha kwenda kwenye programu ya awali              |
| ⌘⇥ (Amri-Tab)                                     | Badilisha kurudi kwenye programu ya awali              |
| ←+→, kisha Chaguo + ← au Chaguo+→                  | Tembea kupitia Dock                                     |

#### Njia fupi za Safari

| Njia Fupi                | Hatua                                           |
| ----------------------- | ---------------------------------------------- |
| ⌘L (Amri-L)            | Fungua Mahali                                  |
| ⌘T                      | Fungua kichupo kipya                           |
| ⌘W                      | Funga kichupo cha sasa                         |
| ⌘R                      | Refresh kichupo cha sasa                       |
| ⌘.                      | Zima kupakia kichupo cha sasa                  |
| ^⇥                      | Badilisha kwenda kwenye kichupo kinachofuata   |
| ^⇧⇥ (Udhibiti-Shift-Tab) | Hamisha kwenda kwenye kichupo kilichopita      |
| ⌘L                      | Chagua uwanja wa kuingiza maandiko/URL ili kuibadilisha |
| ⌘⇧T (Amri-Shift-T)     | Fungua kichupo kilichofungwa mwisho (kinaweza kutumika mara kadhaa) |
| ⌘\[                     | Rudi ukurasa mmoja katika historia yako ya kuvinjari |
| ⌘]                      | Nenda mbele ukurasa mmoja katika historia yako ya kuvinjari |
| ⌘⇧R                     | Washa Modu ya Msomaji                          |

#### Njia fupi za Barua

| Njia Fupi                   | Hatua                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Fungua Mahali                |
| ⌘T                         | Fungua kichupo kipya         |
| ⌘W                         | Funga kichupo cha sasa       |
| ⌘R                         | Refresh kichupo cha sasa     |
| ⌘.                         | Zima kupakia kichupo cha sasa |
| ⌘⌥F (Amri-Chaguo/Alt-F) | Tafuta kwenye sanduku lako la barua |

## Marejeo

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
