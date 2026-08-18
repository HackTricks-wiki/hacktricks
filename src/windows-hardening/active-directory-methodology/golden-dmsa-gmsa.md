# Golden gMSA/dMSA Attack (Managed Service Account Passwords की Offline Derivation)

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Windows Managed Service Accounts ऐसे domain principals हैं जिन्हें administrator द्वारा लंबे समय तक चलने वाले password को संभाले बिना services चलाने के लिए बनाया गया है:

1. **gMSA** (group Managed Service Account) का उपयोग उन computers द्वारा किया जा सकता है जो `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword` के माध्यम से authorised हैं।
2. **dMSA** (delegated Managed Service Account) को **Windows Server 2025** में पेश किया गया था। यह normal authentication को authorised machine identities से bind करता है और migration workflow के माध्यम से legacy service account को replace कर सकता है।

**Golden dMSA** को **BadSuccessor** के साथ confuse न करें। Golden dMSA के लिए KDS root-key material का compromise और managed-account keys की derivation आवश्यक है; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) इसके बजाय dMSA object और उसके migration attributes पर control का abuse करता है।

DC प्रत्येक gMSA के लिए independently generated clear-text password store नहीं करता। यह account password को **KDS root key**, time-indexed Group Key Distribution Protocol (GKDI) key और account SID से derive करता है। Root-key objects `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...` के नीचे स्थित `msKds-ProvRootKey` objects होते हैं; sensitive value `msKds-RootKeyData` है। `msDS-ManagedPasswordId` **GUID नहीं है**: यह एक binary key identifier है जिसमें KDS root-key GUID, GKDI के `L0`/`L1`/`L2` indexes और domain/forest metadata शामिल होते हैं। DC label `GMSA PASSWORD` और binary SID को context के रूप में उपयोग करके KDF लागू करता है, फिर `MSDS-MANAGEDPASSWORD_BLOB` को केवल उन principals के लिए expose करता है जो gMSA password retrieve करने के लिए authorised हैं।<sup>[[2]](#references)</sup>

dMSA सामान्यतः operational रूप से अलग होता है: इसका secret DC पर ही रहने के लिए बनाया जाता है और KDC authorised machine को credentials issue करता है। हालांकि, dMSA underlying KDS/GKDI password derivation का reuse करता है। Golden dMSA उस secret को सीधे reconstruct करता है और इस प्रकार intended machine-bound flow तथा service host पर Credential Guard को bypass करता है।<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

KDS root key extract करने के बाद attacker उन accounts के passwords derive कर सकता है जो उस key से जुड़े हैं, बिना `msDS-ManagedPassword` पढ़े। यह per-account password-retrieval ACL को bypass करता है और सामान्य managed-password rotations के बाद भी काम करता रहता है, जब तक compromised root key उपयोग में है। gMSAs के लिए readable `msDS-ManagedPasswordId` सामान्यतः exact key identifier प्रदान करता है। ACL-restricted dMSAs के लिए Golden dMSA missing identifier को केवल **1,024 candidates** तक सीमित कर देता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisites

* Relevant KDS root-key object, जो सामान्यतः Enterprise Admin / forest-root Domain Admin rights, DC पर `SYSTEM`, या exposed DC database अथवा backup से प्राप्त किया जाता है।<sup>[[1]](#references)[[2]](#references)</sup>
* Target account का SID, DNS domain, forest name और `sAMAccountName`।<sup>[[1]](#references)[[2]](#references)</sup>
* Direct gMSA computation के लिए उसका base64-encoded `msDS-ManagedPasswordId`; Golden dMSA के लिए इसके बजाय इसका guess किया जा सकता है।<sup>[[1]](#references)[[2]](#references)</sup>
* [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) के लिए .NET Framework 4.7.2 वाला x64 Windows host।<sup>[[3]](#references)</sup>

### Phase 1 - KDS root key Extract करें

`GoldenDMSA` और [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) root-key object fields को base64 blob के रूप में export करते हैं। Domain argument के बिना tools forest root को query करते हैं और suitable privileged directory access की आवश्यकता होती है। Domain/forest argument के साथ, DC पर `SYSTEM` उस DC के local Configuration naming-context replica को query कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
दोनों root-key GUID और base64 root-key blob रिकॉर्ड करें। Registry `SECURITY`/`SYSTEM` hive export अपने-आप में KDS root key नहीं है: authoritative material AD Configuration partition में मौजूद होता है।<sup>[[1]](#references)[[2]](#references)</sup>

### चरण 2 - gMSA / dMSA objects की Enumeration

gMSAs के लिए `sAMAccountName`, `objectSid`, और binary `msDS-ManagedPasswordId` प्राप्त करें। बाद वाला सामान्यतः तब भी readable होता है, जब caller को `msDS-ManagedPassword` retrieve करने की अनुमति न हो।<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
dMSA का default ACL low-privileged LDAP enumeration को रोक सकता है। `GoldenDMSA info` या तो LDAP को query कर सकता है या candidate RIDs को enumerate करके `\PIPE\lsarpc` पर `LsaLookupSids` के माध्यम से SIDs resolve कर सकता है, फिर dMSAs को computer accounts और gMSAs से अलग पहचान सकता है।<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### चरण 3 - `msDS-ManagedPasswordId` का पुनर्निर्माण या अनुमान लगाना

मुख्य identifier में `L0Index`, `L1Index`, और `L2Index` शामिल होते हैं, न कि account-creation timestamp के बाद random bits। Semperis ने पाया कि password-generation path candidate `L0Index` का उपयोग नहीं करता, जबकि `L1Index` और `L2Index` प्रत्येक `0..31` मानों तक सीमित होते हैं। परिणामस्वरूप, root-key GUID, domain, forest और SID जानने वाला attacker सभी `32 * 32 = 1,024` संभावित identifiers बना सकता है।<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Derivations offline होते हैं, लेकिन live candidate की पहचान करने के लिए आमतौर पर authentication attempts की आवश्यकता होती है। इससे valid key मिलने से पहले failed Kerberos pre-authentication या NTLM validation की एक burst उत्पन्न हो सकती है। AES Kerberos keys के लिए, tool द्वारा उपयोग किया जाने वाला managed-account salt `UPPERCASE.DNS.DOMAIN` + `host` + trailing `$` के बिना lower-case account UPN होता है (उदाहरण के लिए, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Phase 4 - password compute और use करें

यदि exact identifier ज्ञात है, तो 256-byte password buffer compute करें और उसे NTLM/AES material में convert करें। इन tools द्वारा print किया गया base64 value encoded password buffer है, **न कि स्वयं LDAP `MSDS-MANAGEDPASSWORD_BLOB`।**<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
NTLM result का उपयोग उन स्थानों पर किया जा सकता है जहाँ NTLM स्वीकार किया जाता है; AES key का उपयोग overpass-the-hash / TGT requests के लिए किया जा सकता है, जहाँ managed account केवल AES स्वीकार करता है। इससे compromised managed service account के privileges, SPNs, delegation configuration और resource access प्राप्त होते हैं, attacker की machine को `PrincipalsAllowedToRetrieveManagedPassword` में जोड़े बिना।<sup>[[1]](#references)[[2]](#references)</sup>

### अंतर-डोमेन Configuration-partition का दुरुपयोग

KDS root-key objects forest Configuration naming context में रहते हैं, जो child domains के DCs पर replicate होता है। परिणामस्वरूप, child-domain DC पर `SYSTEM`, child DC के local replica से forest-root KDS material पढ़ सकता है, भले ही child Domain Admins forest-root DC से सीधे object न पढ़ सकें। यदि attacker parent-domain gMSA का `msDS-ManagedPasswordId` भी पढ़ सकता है, तो GoldenGMSA उस parent account का password calculate कर सकता है; SID filtering इस cryptographic attack को नहीं रोकता।<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Detection, Containment और Recovery

* **Master Root Keys** container पर एक SACL configure करें, जो `msKds-ProvRootKey` objects द्वारा inherit हो, और `msKds-RootKeyData` के successful reads के लिए लागू हो। Directory Service Access auditing enabled होने पर, online extraction से Security event **4662** उत्पन्न होता है; ऐसे subjects की जांच करें जो अपेक्षित DCs या Tier-0 operators नहीं हैं। इन SACLs और root-key object ACLs में होने वाले बदलावों का भी audit करें।<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Child-to-parent attack, compromised child DC की local replica से KDS object को read करता है, इसलिए forest-root domain उस read को observe नहीं कर सकता। Parent domain में, `msDS-GroupManagedServiceAccount` objects पर `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) के successful reads का audit करें और किसी अन्य domain के principals द्वारा किए गए reads की जांच करें।<sup>[[5]](#references)</sup>
* KDS-object access को managed accounts के unusual logons और `$`-suffixed service accounts के Kerberos/NTLM failures के bursts के साथ correlate करें। पहले हुए database/backup theft के बाद की गई offline computation किसी live DC पर दिखाई नहीं देती।<sup>[[1]](#references)[[3]](#references)</sup>
* Root-key exposure के बाद सामान्य password rotation पर्याप्त नहीं है। Microsoft's current recovery procedure एक नया KDS root key बनाती है, सभी relevant DCs पर KDS restart करती है, और affected accounts को उस key पर move करती है। यदि exposure का scope/time अज्ञात है और safe roll की प्रतीक्षा करना स्वीकार्य नहीं है, तो compromised key का उपयोग करने वाले प्रत्येक gMSA को replace करें; यदि scope ज्ञात है, तो Microsoft safe rolling को force करने के लिए एक authoritative-restore workflow document करता है। पुराने key को delete करने से पहले `msDS-ManagedPasswordId` में नए key GUID को validate करें।<sup>[[4]](#references)</sup>
* DC database और backup access, Configuration-partition replication, और KDS root-key administration को Tier-0 मानें। `ManagedPasswordIntervalInDays` कम करने से कुछ recovery windows सीमित होती हैं, लेकिन पहले से compromised root key revoke नहीं होती।<sup>[[4]](#references)</sup>

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA enumeration, identifier generation, 1,024-candidate validation, password computation, और NTLM/AES conversion।<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration और online, offline, तथा cross-domain password computation।<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) और [`Impacket`](https://github.com/fortra/impacket) - authorised testing में derived NTLM/AES keys का उपयोग या validation करें।



## References

- [1] [Delegated Managed Service Accounts के लिए Golden dMSA - authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Golden gMSA attack से recover कैसे करें](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [Domains के बीच security boundary के रूप में SID filter? Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
