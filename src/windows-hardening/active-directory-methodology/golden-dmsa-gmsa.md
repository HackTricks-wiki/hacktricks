# Golden gMSA/dMSA Attack (Offline-Ableitung von Managed Service Account-Passwörtern)

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Windows Managed Service Accounts sind Domänenprinzipale, die zum Ausführen von Diensten vorgesehen sind, ohne dass ein Administrator ein langlebiges Passwort verwalten muss:

1. **gMSA** (group Managed Service Account) kann von den Computern verwendet werden, die über `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword` autorisiert sind.
2. **dMSA** (delegated Managed Service Account) wurde in **Windows Server 2025** eingeführt. Es bindet die normale Authentifizierung an autorisierte Computeridentitäten und kann im Rahmen eines Migrations-Workflows ein veraltetes Service Account ersetzen.

Verwechselt **Golden dMSA** nicht mit **BadSuccessor**. Golden dMSA erfordert die Kompromittierung von KDS-root-key-Material und leitet Managed-Account-Schlüssel ab; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) missbraucht dagegen die Kontrolle über ein dMSA-Objekt und dessen Migrationsattribute.

Ein DC speichert kein unabhängig generiertes Klartextpasswort für jedes gMSA. Er leitet das Account-Passwort aus einem **KDS root key**, einem zeitindizierten Group Key Distribution Protocol (GKDI)-Schlüssel und der Account-SID ab. Die Root-Key-Objekte sind `msKds-ProvRootKey`-Objekte unterhalb von `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; der sensitive Wert ist `msKds-RootKeyData`. `msDS-ManagedPasswordId` ist **keine GUID**: Es handelt sich um einen binären Schlüsselbezeichner, der die GUID des KDS root key, die GKDI-Indizes `L0`/`L1`/`L2` sowie Domänen-/Forest-Metadaten enthält. Der DC wendet die KDF mit dem Label `GMSA PASSWORD` und der binären SID als Kontext an und stellt anschließend ein `MSDS-MANAGEDPASSWORD_BLOB` nur für Prinzipale bereit, die zum Abrufen eines gMSA-Passworts autorisiert sind.<sup>[[2]](#references)</sup>

Ein dMSA unterscheidet sich normalerweise im operativen Verhalten: Sein Secret soll auf dem DC verbleiben, und der KDC stellt einem autorisierten Computer Credentials aus. dMSAs verwenden jedoch weiterhin die zugrunde liegende KDS/GKDI-Passwortableitung. Golden dMSA rekonstruiert dieses Secret direkt und umgeht dadurch den vorgesehenen, an den Computer gebundenen Ablauf sowie Credential Guard auf dem Service Host.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Nach dem Extrahieren eines KDS root key kann ein Angreifer Passwörter für Accounts ableiten, die an diesen Schlüssel gebunden sind, ohne `msDS-ManagedPassword` auszulesen. Dadurch wird die ACL für den kontenbezogenen Passwortabruf umgangen; außerdem bleibt der Zugriff über normale Managed-Password-Rotationen hinweg bestehen, solange der kompromittierte Root Key verwendet wird. Bei gMSAs liefert die lesbare `msDS-ManagedPasswordId` normalerweise den exakten Schlüsselbezeichner. Bei ACL-beschränkten dMSAs reduziert Golden dMSA den fehlenden Bezeichner auf nur **1.024 Kandidaten**.<sup>[[1]](#references)[[2]](#references)</sup>

### Voraussetzungen

* Das relevante KDS-root-key-Objekt, üblicherweise erlangt mit Enterprise-Admin-/Forest-Root-Domain-Admin-Rechten, als `SYSTEM` auf einem DC oder aus einer offengelegten DC-Datenbank bzw. einem Backup.<sup>[[1]](#references)[[2]](#references)</sup>
* Die SID des Ziel-Accounts, die DNS-Domäne, der Forest-Name und `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Für die direkte gMSA-Berechnung dessen base64-kodierte `msDS-ManagedPasswordId`; für Golden dMSA kann dieser stattdessen erraten werden.<sup>[[1]](#references)[[2]](#references)</sup>
* Ein x64-Windows-Host mit .NET Framework 4.7.2 für [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Phase 1 - KDS root key extrahieren

`GoldenDMSA` und [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) exportieren die Felder des Root-Key-Objekts als base64-Blob. Ohne ein Domänenargument fragen die Tools den Forest Root ab und benötigen dafür geeigneten privilegierten Directory-Zugriff. Mit dem Domänen-/Forest-Argument kann `SYSTEM` auf einem DC das lokale Configuration-Naming-Context-Replikat dieses DCs abfragen.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Speichern Sie sowohl die GUID des root key als auch den base64-Blob des root key. Ein Export der `SECURITY`-/`SYSTEM`-Registry-Hive ist nicht allein der KDS root key: Das maßgebliche Material befindet sich in der AD Configuration partition.<sup>[[1]](#references)[[2]](#references)</sup>

### Phase 2 - gMSA-/dMSA-Objekte auflisten

Ermitteln Sie für gMSAs `sAMAccountName`, `objectSid` und die binäre Eigenschaft `msDS-ManagedPasswordId`. Letztere ist normalerweise lesbar, selbst wenn der aufrufende Benutzer nicht berechtigt ist, `msDS-ManagedPassword` abzurufen.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
Die Standard-ACL einer dMSA kann die LDAP-Aufzählung für Benutzer mit niedrigen Berechtigungen verhindern. `GoldenDMSA info` kann entweder LDAP abfragen oder Kandidaten-RIDs aufzählen und SIDs über `LsaLookupSids` mittels `\PIPE\lsarpc` auflösen und anschließend dMSAs von Computerkonten und gMSAs unterscheiden.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Phase 3 – `msDS-ManagedPasswordId` rekonstruieren oder erraten

Der Schlüsselbezeichner enthält `L0Index`, `L1Index` und `L2Index`, nicht einen Zeitstempel der Kontoerstellung gefolgt von zufälligen Bits. Semperis stellte fest, dass der Pfad zur Passwortgenerierung den Kandidaten `L0Index` nicht verwendet, während `L1Index` und `L2Index` jeweils auf die Werte `0..31` beschränkt sind. Folglich kann ein Angreifer, der die GUID des Root-Schlüssels, die Domäne, die Gesamtstruktur und die SID kennt, alle `32 * 32 = 1.024` möglichen Bezeichner konstruieren.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Die Ableitungen erfolgen offline, aber die Identifizierung des aktiven Kandidaten erfordert normalerweise Authentifizierungsversuche. Dadurch kann eine Folge fehlgeschlagener Kerberos-Pre-Authentication- oder NTLM-Validierungsversuche entstehen, bevor der gültige Schlüssel gefunden wird. Für AES-Kerberos-Schlüssel ist der vom Tool verwendete Salt des verwalteten Kontos `UPPERCASE.DNS.DOMAIN` + `host` + der kleingeschriebene Account-UPN ohne nachgestelltes `$` (zum Beispiel `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Phase 4 - Passwort berechnen und verwenden

Wenn der genaue Identifier bekannt ist, berechne den 256-Byte-Puffer des Passworts und konvertiere ihn in NTLM/AES-Material. Der von diesen Tools ausgegebene Base64-Wert ist der codierte Passwortpuffer, **nicht** der LDAP-`MSDS-MANAGEDPASSWORD_BLOB` selbst.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
Das NTLM-Ergebnis kann dort verwendet werden, wo NTLM akzeptiert wird; der AES-Schlüssel kann für overpass-the-hash / TGT requests verwendet werden, wenn das verwaltete Konto nur AES unterstützt. Dadurch erhält der Angreifer die Berechtigungen, SPNs, Delegation-Konfiguration und den Ressourcenzugriff des kompromittierten verwalteten Dienstkontos, ohne die Maschine des Angreifers zu `PrincipalsAllowedToRetrieveManagedPassword` hinzuzufügen.<sup>[[1]](#references)[[2]](#references)</sup>

### Missbrauch der Configuration-Partition über Domänengrenzen hinweg

KDS-root-key-Objekte befinden sich im Configuration naming context der Forest, der zu DCs in untergeordneten Domänen repliziert wird. Folglich kann `SYSTEM` auf einem DC einer untergeordneten Domäne das KDS-Material der Forest-Root aus der lokalen Replik des untergeordneten DCs lesen, obwohl Domain Admins der untergeordneten Domäne das Objekt nicht direkt von einem DC der Forest-Root lesen können. Wenn der Angreifer außerdem `msDS-ManagedPasswordId` einer gMSA der übergeordneten Domäne lesen kann, kann GoldenGMSA das Passwort dieses übergeordneten Kontos berechnen; SID filtering verhindert diesen kryptografischen Angriff nicht.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Erkennung, Eindämmung und Wiederherstellung

* Konfigurieren Sie eine SACL für den Container **Master Root Keys**, die von `msKds-ProvRootKey`-Objekten geerbt wird, um erfolgreiche Lesezugriffe auf `msKds-RootKeyData` zu erfassen. Bei aktivierter Überwachung von Directory Service Access erzeugt eine online durchgeführte Extraktion das Security-Ereignis **4662**; untersuchen Sie Subjekte, bei denen es sich nicht um erwartete DCs oder Tier-0-Operatoren handelt. Überwachen Sie außerdem Änderungen an diesen SACLs und den ACLs der Root-Key-Objekte.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Ein Child-to-Parent-Angriff liest das KDS-Objekt aus der lokalen Replik des kompromittierten Child-DCs, sodass die Forest-Root-Domain diesen Lesezugriff möglicherweise nicht beobachtet. Überwachen Sie in der Parent-Domain erfolgreiche Lesezugriffe auf `msDS-ManagedPasswordId` (Schema-GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) für `msDS-GroupManagedServiceAccount`-Objekte und untersuchen Sie Lesezugriffe durch Principals aus einer anderen Domain.<sup>[[5]](#references)</sup>
* Korrelieren Sie Zugriffe auf KDS-Objekte mit ungewöhnlichen Logons durch verwaltete Accounts sowie mit Häufungen von Kerberos-/NTLM-Fehlern für Service-Accounts mit dem Suffix `$`. Eine Offline-Berechnung nach einem vorherigen Diebstahl der Datenbank oder eines Backups ist für einen aktiven DC nicht sichtbar.<sup>[[1]](#references)[[3]](#references)</sup>
* Eine gewöhnliche Passwortrotation reicht nach einer Kompromittierung des Root Keys nicht aus. Microsofts aktuelles Wiederherstellungsverfahren erstellt einen neuen KDS Root Key, startet KDS auf allen relevanten DCs neu und verschiebt betroffene Accounts zu diesem Key. Wenn Umfang oder Zeitpunkt der Offenlegung unbekannt sind und das Warten auf einen sicheren Roll unzumutbar ist, ersetzen Sie jeden gMSA, der den kompromittierten Key verwendet hat; wenn der Umfang bekannt ist, dokumentiert Microsoft einen Authoritative-Restore-Workflow, um ein sicheres Rolling zu erzwingen. Validieren Sie die neue Key-GUID in `msDS-ManagedPasswordId`, bevor Sie den alten Key löschen.<sup>[[4]](#references)</sup>
* Behandeln Sie den Zugriff auf DC-Datenbanken und Backups, die Replikation der Configuration-Partition sowie die Administration von KDS Root Keys als Tier-0. Eine Reduzierung von `ManagedPasswordIntervalInDays` begrenzt einige Wiederherstellungszeiträume, widerruft jedoch keinen bereits kompromittierten Root Key.<sup>[[4]](#references)</sup>

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA-Aufzählung, Generierung von Identifiers, Validierung von 1.024 Kandidaten, Passwortberechnung und NTLM-/AES-Konvertierung.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA-/KDS-Aufzählung sowie Online-, Offline- und domainübergreifende Passwortberechnung.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) und [`Impacket`](https://github.com/fortra/impacket) - verwenden oder validieren Sie die abgeleiteten NTLM-/AES-Keys in autorisierten Tests.



## References

- [1] [Golden dMSA - Authentifizierungsumgehung für delegierte Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory-Angriffe](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub-Repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Wiederherstellung nach einem Golden-gMSA-Angriff](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID-Filter als Sicherheitsgrenze zwischen Domains? Teil 5 - Golden-gMSA-Trust-Angriff](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
