# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Recent Windows builds introduced **SMB client support for alternative TCP ports**. That feature can be abused to turn **local NTLM authentication** into a **SYSTEM local privilege escalation** when the attacker can:

1. Open an SMB connection to an attacker-controlled listener on a **non-445 port**
2. Keep that TCP connection alive
3. Coerce a **privileged local client** to access the **same SMB share path**
4. Relay the resulting **local NTLM authentication** back to the machine's real SMB service

This is the primitive behind **CVE-2026-24294**, patched in **March 2026**.

## Why it works

The older CMTI / serialized-SPN reflection trick is covered here:

{{#ref}}
../ntlm/README.md
{{#endref}}

This newer variant does **not** need a marshalled hostname. Instead it abuses two SMB client behaviours:

- **Alternative port support** on **Windows 11 24H2** and **Windows Server 2025**, exposed to users with `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, where multiple authenticated sessions can ride the same TCP connection

That means a low-privileged user can first create a TCP connection from the SMB client to an attacker SMB server on a high port, then coerce a privileged service to access the **exact same UNC path**. If Windows decides to reuse the existing TCP connection, the privileged NTLM exchange is sent over the attacker-controlled transport and can be relayed to the local SMB server.

## Preconditions

- Target supports SMB alternative ports:
  - **Windows 11 24H2** or later
  - **Windows Server 2025** or later
- The attacker can run a local or remote SMB server on a chosen high port
- The attacker can coerce a privileged service to access a UNC path
- The privileged authentication must be **NTLM local authentication**
- The target must be relayable:
  - Synacktiv reported it worked by default on **Windows Server 2025**
  - Their chain did **not** work on **Windows 11 24H2** because outbound SMB signing is enforced there by default

## Userland and internals

From the command line the feature looks simple:

```cmd
net use \\192.168.56.3\share /tcpport:12345
```

Programmatically, the client uses `WNetAddConnection4W` with undocumented `lpUseOptions` data. The relevant option is `TraP` (transport parameters), which eventually reaches the kernel SMB client through an FSCTL and is parsed by `mrxsmb`.

Important practical notes:

- **UNC syntax still has no port field**
- **`net use` is per-logon-session**
- The bypass still works because **the TCP connection and the SMB session are separate objects**
- Reusing the **same share path** is mandatory if the exploit depends on the SMB client reusing the previously created TCP connection

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Run an SMB server on a high port and make Windows connect to it:

```cmd
net use \\192.168.56.3\share /tcpport:12345
```

The server can accept any credential pair you control, for example `user:user`. The goal of this step is not privilege escalation yet, only to make the Windows SMB client open and keep a reusable TCP connection to your listener.

### 2. Coerce a privileged service to the same UNC path

Use a coercion primitive such as **PetitPotam** against the **same** `\\192.168.56.3\share` path. If the coerced client is privileged and the target name is local (`localhost` or a local IP/host), Windows performs **NTLM local authentication**.

Because the TCP connection is reused, that privileged NTLM exchange travels to the attacker SMB service instead of directly to the real local SMB server.

### 3. Relay the privileged authentication back to local SMB

The attacker-controlled SMB service forwards the privileged NTLM exchange to `ntlmrelayx.py`, which relays it to the machine's real SMB listener and obtains a session as `NT AUTHORITY\SYSTEM`.

Typical tooling from the public writeup:

- `smbserver.py` on a custom port to receive the privileged auth over the reused TCP connection
- `ntlmrelayx.py` to relay the captured NTLM to local SMB
- `PetitPotam.exe` or another coercion primitive to force the privileged authentication

## Operator notes

- This is a **local privilege escalation** technique, not a generic remote relay trick
- The attacker-controlled SMB service must handle the privileged authentication on the **same TCP connection** originally used for the share mount
- If the coerced access hits a **different share path**, Windows may establish a different connection and the chain breaks
- SMB signing requirements can kill the relay even when the arbitrary-port step works
- If you only have Kerberos material or cannot force local NTLM, this exact variant is not enough

## Detection and hardening

- Patch **CVE-2026-24294** from **March 2026 Patch Tuesday**
- Watch for `net use` or `New-SmbMapping` using **non-default SMB ports**
- Alert on unusual outbound SMB from workstations or servers to **high TCP ports**
- Review coercion opportunities such as **EFSRPC / PetitPotam-style** triggers
- Enforce SMB signing where possible; Synacktiv specifically notes this blocked their relay on Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
