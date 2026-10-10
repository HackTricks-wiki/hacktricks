# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Golden ticket की तरह**, diamond ticket एक TGT है जिसका इस्तेमाल **किसी भी user के रूप में किसी भी service को access करने** के लिए किया जा सकता है। Golden ticket पूरी तरह offline forge किया जाता है, उस domain के krbtgt hash से encrypt किया जाता है, और फिर इस्तेमाल के लिए logon session में डाला जाता है। चूँकि domain controllers यह track नहीं करते कि उन्होंने कौन-से TGT वैध रूप से जारी किए हैं, इसलिए वे अपने krbtgt hash से encrypt किए गए TGT को खुशी-खुशी स्वीकार कर लेते हैं।<sup>[[1]](#references)</sup>

Golden ticket के इस्तेमाल का पता लगाने के लिए दो आम techniques हैं:

- ऐसे TGS-REQs खोजें जिनके पहले कोई संबंधित AS-REQ न हो।
- ऐसे TGTs खोजें जिनमें असामान्य values हों, जैसे Mimikatz की default 10-year lifetime।

**Diamond ticket**, **DC द्वारा जारी किए गए वैध TGT के fields को modify करके** बनाया जाता है। इसके लिए **TGT को request** किया जाता है, domain के krbtgt hash से उसे **decrypt** किया जाता है, ticket के इच्छित fields को **modify** किया जाता है, और फिर उसे **दोबारा encrypt** किया जाता है। इससे golden ticket की ऊपर बताई गई दोनों कमियाँ दूर हो जाती हैं, क्योंकि:<sup>[[1]](#references)</sup>

- TGS-REQs से पहले AS-REQ होगा।
- TGT, DC द्वारा जारी किया गया था, इसलिए उसमें domain की Kerberos policy की सभी सही details होंगी। Golden ticket में भी इन्हें सटीक रूप से forge किया जा सकता है, लेकिन यह अधिक जटिल है और इसमें गलतियाँ होने की संभावना रहती है।

### आवश्यकताएँ और workflow

- **Cryptographic material**: TGT को decrypt और re-sign करने के लिए krbtgt AES256 key (पसंदीदा) या NTLM hash।
- **वैध TGT blob**: `/tgtdeleg`, `asktgt`, `s4u` या memory से tickets export करके प्राप्त किया गया।
- **Context data**: target user RID, group RIDs/SIDs, और (वैकल्पिक रूप से) LDAP से प्राप्त PAC attributes।
- **Service keys** (केवल तभी, जब आप service tickets को दोबारा बनाना चाहते हैं): impersonate किए जाने वाले service SPN की AES key।

1. AS-REQ के ज़रिए किसी भी नियंत्रित user के लिए TGT प्राप्त करें (`/tgtdeleg` वाला Rubeus सुविधाजनक है, क्योंकि यह client को credentials के बिना Kerberos GSS-API प्रक्रिया पूरी करने के लिए प्रेरित करता है)।
2. लौटाए गए TGT को krbtgt key से decrypt करें और PAC attributes (user, groups, logon info, SIDs, device claims आदि) patch करें।
3. उसी krbtgt key से ticket को दोबारा encrypt/sign करें और उसे मौजूदा logon session में inject करें (`kerberos::ptt`, `Rubeus.exe ptt`...)।
4. वैकल्पिक रूप से, wire पर stealth बनाए रखने के लिए वैध TGT blob और target service key देकर service ticket पर भी यही प्रक्रिया दोहराएँ।

### Rubeus tradecraft में अपडेट (2024+)

Huntress के हालिया काम ने `/ldap` और `/opsec` सुधारों को port करके Rubeus के `diamond` action को आधुनिक बनाया है। ये सुधार पहले केवल golden/silver tickets के लिए उपलब्ध थे। `/ldap` अब LDAP query करके **और** SYSVOL mount करके वास्तविक PAC context प्राप्त करता है, जिसमें account/group attributes और Kerberos/password policy (जैसे `GptTmpl.inf`) शामिल हैं। वहीं, `/opsec` दो-चरणों वाला preauth exchange करके और केवल AES + वास्तविक KDCOptions लागू करके AS-REQ/AS-REP flow को Windows के अनुरूप बनाता है। इससे PAC fields का गायब होना या policy से मेल न खाने वाली lifetimes जैसे स्पष्ट indicators काफ़ी कम हो जाते हैं।<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (`/ldapuser` और `/ldappassword` वैकल्पिक हैं) AD और SYSVOL को query करके target user का PAC policy data मिरर करता है।
- `/opsec` Windows-जैसी AS-REQ retry को बाध्य करता है, शोर करने वाले flags को zero करके AES256 पर टिके रहता है।
- `/tgtdeleg` आपको victim के cleartext password या NTLM/AES key को छुए बिना एक decryptable TGT देता है।

### Service-ticket recutting

उसी Rubeus refresh में TGS blobs पर diamond technique लागू करने की क्षमता जोड़ी गई। `diamond` को **base64-encoded TGT** (`asktgt`, `/tgtdeleg` या पहले से forged TGT से), **service SPN**, और **service AES key** देकर, आप KDC को छुए बिना यथार्थवादी service tickets बना सकते हैं—प्रभावी रूप से एक अधिक stealthy silver ticket।<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

यह workflow तब आदर्श है जब आपके पास पहले से किसी service account की key का control हो (जैसे, `lsadump::lsa /inject` या `secretsdump.py` से dump की गई) और आप AD policy, timelines और PAC data से पूरी तरह मेल खाने वाला one-off TGS बनाना चाहते हों—बिना कोई नया AS/TGS traffic भेजे।<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

एक नया रूप, जिसे कभी-कभी **sapphire ticket** कहा जाता है, Diamond के "real TGT" base को **S4U2self+U2U** के साथ मिलाकर एक privileged PAC चुराता है और उसे आपके अपने TGT में डालता है। अतिरिक्त SIDs गढ़ने के बजाय, आप एक high-privilege user के लिए U2U S4U2self ticket का अनुरोध करते हैं, जिसमें `sname` low-priv requester को target करता है; KRB_TGS_REQ में requester का TGT `additional-tickets` में होता है और `ENC-TKT-IN-SKEY` सेट होता है, जिससे service ticket को उस user की key से decrypt किया जा सकता है। इसके बाद आप privileged PAC निकालकर उसे अपने legitimate TGT में splice करते हैं और krbtgt key से फिर से sign करते हैं।<sup>[[2]](#references)[[5]](#references)</sup>

Impacket का `ticketer.py` अब `-impersonate` + `-request` के ज़रिए sapphire support देता है (live KDC exchange):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` username या SID स्वीकार करता है; `-request` को tickets decrypt/patch करने के लिए live user creds और krbtgt key material (AES/NTLM) चाहिए।

इस variant का उपयोग करते समय OPSEC के मुख्य संकेत:<sup>[[5]](#references)</sup>

- TGS-REQ में `ENC-TKT-IN-SKEY` और `additional-tickets` (victim TGT) होंगे — सामान्य traffic में यह दुर्लभ है।
- `sname` अक्सर requesting user के बराबर होता है (self-service access), और Event ID 4769 में caller और target एक ही SPN/user के रूप में दिखते हैं।
- समान client computer के साथ, लेकिन अलग CNAMES (low-priv requester बनाम privileged PAC owner) वाली 4768/4769 entries की जोड़ी दिखने की अपेक्षा करें।

### OPSEC और detection संबंधी नोट्स

- पारंपरिक hunter heuristics (AS के बिना TGS, एक दशक तक की lifetimes) golden tickets के लिए अब भी लागू होते हैं, लेकिन diamond tickets मुख्यतः तब सामने आते हैं जब **PAC content या group mapping असंभव लगती है**। PAC के हर field (logon hours, user profile paths, device IDs) को भरें, ताकि automated comparisons forgery को तुरंत flag न करें।<sup>[[3]](#references)</sup>
- **Groups/RIDs की जरूरत से ज्यादा संख्या न जोड़ें**। अगर आपको केवल `512` (Domain Admins) और `519` (Enterprise Admins) चाहिए, तो वहीं रुकें और सुनिश्चित करें कि target account AD में अन्य जगहों पर भी विश्वसनीय रूप से इन groups का सदस्य हो। जरूरत से ज्यादा `ExtraSids` संदेह पैदा करते हैं।
- Sapphire-style swaps U2U के fingerprints छोड़ते हैं: `ENC-TKT-IN-SKEY` + `additional-tickets`, साथ ही 4769 में user (अक्सर requester) की ओर संकेत करता `sname`, और forged ticket से आया follow-up 4624 logon। केवल no-AS-REQ gaps देखने के बजाय इन fields का correlation करें।<sup>[[5]](#references)</sup>
- Microsoft ने CVE-2026-20833 के कारण **RC4 service ticket issuance** को चरणबद्ध तरीके से बंद करना शुरू कर दिया है; KDC पर AES-only etypes लागू करने से domain अधिक सुरक्षित होता है और diamond/sapphire tooling के अनुरूप भी रहता है (/opsec पहले से AES लागू करता है)। Forged PACs में RC4 मिलाने से वे तेजी से अलग दिखाई देंगे।<sup>[[6]](#references)</sup>
- Splunk का Security Content project diamond tickets के लिए attack-range telemetry और *Windows Domain Admin Impersonation Indicator* जैसे detections वितरित करता है, जो असामान्य Event ID 4768/4769/4624 sequences और PAC group changes का correlation करते हैं। उस dataset को replay करना (या ऊपर दिए गए commands से अपना dataset बनाना) T1558.001 के लिए SOC coverage को validate करने में मदद करता है और साथ ही बच निकलने के लिए ठोस alert logic भी देता है।<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – कीमती रत्न: Kerberos हमलों की नई पीढ़ी (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: हमें Tickets खेलना पसंद है (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Kerberos Diamond Ticket को फिर से गढ़ना (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data और detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – रत्नों का छाया पक्ष: Diamond और Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – CVE-2026-20833 के लिए RC4 service ticket enforcement](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
