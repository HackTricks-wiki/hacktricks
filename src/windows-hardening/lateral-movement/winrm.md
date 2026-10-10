# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM Windows वातावरणों में सबसे सुविधाजनक **lateral movement** transports में से एक है, क्योंकि यह SMB service creation tricks की ज़रूरत के बिना **WS-Man/HTTP(S)** पर remote shell देता है। यदि target **5985/5986** expose करता है और आपके principal को remoting की अनुमति है, तो आप अक्सर "valid creds" से "interactive shell" तक बहुत जल्दी पहुँच सकते हैं।

**Protocol/service enumeration**, listeners, WinRM enable करने, `Invoke-Command` और सामान्य client usage के लिए देखें:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operators को WinRM क्यों पसंद है

- **SMB/RPC** के बजाय **HTTP/HTTPS** का उपयोग करता है, इसलिए यह अक्सर वहाँ काम करता है जहाँ PsExec-style execution blocked होता है।
- **Kerberos** के साथ, यह target को दोबारा इस्तेमाल किए जा सकने वाले credentials भेजने से बचाता है।
- **Windows**, **Linux** और **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) से आसानी से काम करता है।
- Interactive PowerShell remoting path, authenticated user context में target पर **`wsmprovhost.exe`** spawn करता है, जो service-based exec से operational रूप से अलग है।

## Access model और prerequisites

व्यवहार में, सफल WinRM lateral movement **तीन** चीज़ों पर निर्भर करता है:

1. Target पर **WinRM listener** (`5985`/`5986`) हो और firewall rules access की अनुमति दें।
2. Account endpoint पर **authenticate** कर सके।
3. Account को **remoting session खोलने** की अनुमति हो।

यह access पाने के आम तरीके:

- Target पर **Local Administrator** होना।
- नए systems पर **Remote Management Users** का सदस्य होना या उन systems/components पर **WinRMRemoteWMIUsers__** का सदस्य होना जो अब भी उस group को मान्यता देते हैं।
- Local security descriptors / PowerShell remoting ACL में बदलावों के ज़रिए स्पष्ट रूप से remoting rights delegate किए गए हों।

यदि आपके पास पहले से admin rights वाला कोई box है, तो याद रखें कि यहाँ बताई गई techniques का उपयोग करके **पूरी admin group membership के बिना भी WinRM access delegate** किया जा सकता है:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication की वे समस्याएँ जो lateral movement के दौरान मायने रखती हैं

- **Kerberos के लिए hostname/FQDN ज़रूरी है**। यदि आप IP से connect करते हैं, तो client आम तौर पर **NTLM/Negotiate** पर fallback करता है।
- **Workgroup** या cross-trust edge cases में, NTLM के लिए आम तौर पर **HTTPS** या client पर target को **TrustedHosts** में जोड़ना ज़रूरी होता है।
- Workgroup में Negotiate के ज़रिए **local accounts** इस्तेमाल करते समय, UAC remote restrictions access रोक सकती हैं, जब तक कि built-in Administrator account का उपयोग न किया जाए या `LocalAccountTokenFilterPolicy=1` न हो।
- PowerShell remoting में default रूप से **`HTTP/<host>` SPN** का उपयोग होता है। जिन environments में **`HTTP/<host>`** पहले से किसी अन्य service account के लिए registered है, वहाँ WinRM Kerberos `0x80090322` के साथ fail हो सकता है; port-qualified SPN का उपयोग करें या **`WSMAN/<host>`** पर switch करें, जहाँ वह SPN मौजूद हो।<sup>[[3]](#references)</sup>

यदि password spraying के दौरान आपको valid credentials मिलते हैं, तो WinRM पर उन्हें validate करना अक्सर यह जाँचने का सबसे तेज़ तरीका होता है कि क्या उनसे shell मिल सकती है:

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

`evil-winrm` Linux से interactive shells के लिए सबसे सुविधाजनक विकल्प बना हुआ है, क्योंकि यह **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer और in-memory PowerShell/.NET loading को support करता है।

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN का विशेष मामला: `HTTP` बनाम `WSMAN`

जब default **`HTTP/<host>`** SPN के कारण Kerberos failures हों, तो इसके बजाय **`WSMAN/<host>`** ticket request/use करने की कोशिश करें। ऐसा hardened या असामान्य enterprise setups में देखने को मिलता है, जहाँ `HTTP/<host>` पहले से किसी दूसरे service account से जुड़ा होता है।<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

यह **RBCD / S4U** abuse के बाद भी उपयोगी है, जब आपने generic `HTTP` ticket के बजाय विशेष रूप से **WSMAN** service ticket forge किया हो या request किया हो।

### Certificate-based authentication

WinRM **client certificate authentication** को भी support करता है, लेकिन certificate को target पर किसी **local account** से map करना ज़रूरी है। Offensive perspective से यह इन स्थितियों में महत्वपूर्ण है:

- आपने WinRM के लिए पहले से mapped valid client certificate और private key चुराई/export की हो;
- आपने किसी principal के लिए certificate पाने के लिए **AD CS / Pass-the-Certificate** abuse किया हो और फिर किसी दूसरे authentication path में pivot किया हो;
- आप ऐसे environments में काम कर रहे हों जहाँ password-based remoting से जानबूझकर बचा जाता है।

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM, password/hash/Kerberos auth की तुलना में बहुत कम आम है, लेकिन जहाँ यह मौजूद हो, वहाँ यह **passwordless lateral movement** का रास्ता दे सकता है, जो password rotation के बाद भी काम करता है।

### Python / automation with `pypsrp`

अगर आपको operator shell के बजाय automation चाहिए, तो `pypsrp` Python से WinRM/PSRP उपलब्ध कराता है और इसमें **NTLM**, **certificate auth**, **Kerberos**, और **CredSSP** का support है।<sup>[[2]](#references)</sup>

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


अगर आपको high-level `Client` wrapper से ज़्यादा बारीक नियंत्रण चाहिए, तो निचले-स्तर के `WSMan` + `RunspacePool` APIs दो आम operator समस्याओं के लिए उपयोगी हैं:

- default `HTTP` expectation के बजाय Kerberos service/SPN के रूप में **`WSMAN`** को बाध्य करना, जिसका उपयोग कई PowerShell clients करते हैं;
- **`Microsoft.PowerShell`** के बजाय किसी **JEA** / custom session configuration जैसे **non-default PSRP endpoint** से कनेक्ट करना।

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

### Lateral movement के दौरान Custom PSRP endpoints और JEA महत्वपूर्ण हैं

सफल WinRM authentication का **यह अर्थ हमेशा नहीं होता कि आपको default unrestricted `Microsoft.PowerShell` endpoint मिलता है**। परिपक्व environments में अपने ACLs और run-as behavior वाले **custom session configurations** या **JEA** endpoints उपलब्ध हो सकते हैं।<sup>[[1]](#references)</sup>

यदि आपके पास पहले से किसी Windows host पर code execution है और आप जानना चाहते हैं कि कौन-से remoting surfaces उपलब्ध हैं, तो registered endpoints enumerate करें:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

जब कोई उपयोगी endpoint उपलब्ध हो, तो default shell के बजाय उसे स्पष्ट रूप से target करें:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Practical offensive implications:

- **restricted** endpoint lateral movement के लिए पर्याप्त हो सकता है, अगर उसमें service control, file access, process creation या arbitrary .NET / external command execution के लिए सही cmdlets/functions उपलब्ध हों।
- **misconfigured JEA** role खास तौर पर उपयोगी होता है, अगर उसमें `Start-Process` जैसे खतरनाक commands, broad wildcards, writable providers या custom proxy functions उपलब्ध हों, जिनसे intended restrictions से बाहर निकला जा सके।
- **RunAs virtual accounts** या **gMSAs** से backed endpoints आपके चलाए गए commands का effective security context बदल देते हैं। खास तौर पर, gMSA-backed endpoint **second hop पर network identity** दे सकता है, जबकि सामान्य WinRM session में classic delegation problem आ सकती है।

किसी custom restricted endpoint के लिए, उसकी effective command और script permissions की अलग-अलग जाँच करें: केवल `Get-Command` की छोटी सूची से यह साबित नहीं होता कि कोई मौजूदा `.ps1` नहीं चल सकती। [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) स्पष्ट रूप से नियंत्रित करती हैं कि कौन-से script paths invoke किए जा सकते हैं; अन्य custom endpoints अलग session rules लागू कर सकते हैं। अगर अनुमति प्राप्त script किसी दूसरे host के लिए credential बनाने हेतु stored `SecureString` का उपयोग करती है, तो explicit key के बिना बनाया गया blob [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) का उपयोग करता है और उसे decrypt करने के लिए आम तौर पर उसे protect करने वाले user और machine का context चाहिए। Writable source या copied blob को cross-host escalation path मानने से पहले script का ACL, अनुमत invocation, run-as identity और downstream credential rights जाँचें। Passive enumeration के दौरान protected value प्रिंट न करें।

ऐसे JEA custom function के लिए जो file path स्वीकार करता है, registered endpoint ACL, mapped role capability और effective run-as identity को एक साथ जाँचें। Caller के पास `NoLanguage` हो सकता है, जबकि function body system के default language mode में चलती है; virtual account के पास local administrator rights भी हो सकते हैं। अगर function raw string prefix से allowed directory जाँचता है और बाद में दिए गए path को पढ़ता है, तो `..` components उस directory के बाहर resolve हो सकते हैं। सीमा वह resolved path है जिसे function की identity के तहत देखा जाता है—caller का language mode या दिखने वाला prefix नहीं। किसी readable `.psrc` या `.pssc` file को privileged file-read finding मानने से पहले, उपलब्ध function और उसकी final-path validation की पुष्टि करें। Microsoft की [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) और [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations) guidance देखें।

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` built in है और तब उपयोगी है जब आप interactive PowerShell remoting session खोले बिना **native WinRM command execution** चाहते हैं:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

दो flags को भूलना आसान है, लेकिन व्यवहार में ये महत्वपूर्ण हैं:

- जब remote principal **local administrator** न हो, तो अक्सर `/noprofile` की आवश्यकता होती है।
- `/allowdelegate` remote shell को **तीसरे host** के विरुद्ध आपके credentials का उपयोग करने देता है (उदाहरण के लिए, जब command को `\\fileserver\share` की आवश्यकता हो)।

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

व्यवहार में, `winrs.exe` से आमतौर पर इस तरह की remote process chain बनती है:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

यह याद रखने योग्य है, क्योंकि यह service-based exec और interactive PSRP sessions से अलग है।

### `winrm.cmd` / PowerShell remoting के बजाय WS-Man COM

आप `Enter-PSSession` के बिना भी WS-Man के ज़रिए WMI classes invoke करके **WinRM transport** के माध्यम से execute कर सकते हैं। इससे transport WinRM ही रहता है, जबकि remote execution primitive **WMI `Win32_Process.Create`** बन जाता है:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

यह तरीका तब उपयोगी है, जब:

- PowerShell logging की कड़ी निगरानी की जाती हो।
- आप **WinRM transport** चाहते हों, लेकिन classic PS remoting workflow नहीं।
- आप **`WSMan.Automation`** COM object के आसपास custom tooling बना रहे हों या उसका उपयोग कर रहे हों।

## WinRM (WS-Man) पर NTLM relay

जब signing के कारण SMB relay ब्लॉक हो और LDAP relay सीमित हो, तब भी **WS-Man/WinRM** एक आकर्षक relay target हो सकता है। आधुनिक `ntlmrelayx.py` में **WinRM relay servers** शामिल हैं और यह **`wsman://`** या **`winrms://`** targets पर relay कर सकता है।

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

दो व्यावहारिक नोट:

- Relay सबसे उपयोगी तब होता है जब target **NTLM** स्वीकार करता हो और relayed principal को WinRM इस्तेमाल करने की अनुमति हो।
- हाल के Impacket code में **`WSMANIDENTIFY: unauthenticated`** requests को विशेष रूप से संभाला जाता है, ताकि `Test-WSMan`-style probes relay flow को बाधित न करें।

पहला WinRM session मिलने के बाद multi-hop संबंधी सीमाओं के लिए देखें:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC और detection संबंधी नोट

- **Interactive PowerShell remoting** आमतौर पर target पर **`wsmprovhost.exe`** बनाता है।
- **`winrs.exe`** आमतौर पर **`winrshost.exe`** बनाता है, जिसके बाद अनुरोधित child process बनता है।
- Custom **JEA** endpoints, सामान्य user-context shell की तुलना में telemetry और second-hop behavior को बदलते हुए, actions को **`WinRM_VA_*`** virtual accounts या configured **gMSA** के रूप में execute कर सकते हैं।<sup>[[1]](#references)</sup>
- यदि आप raw `cmd.exe` के बजाय PSRP इस्तेमाल करते हैं, तो network logon telemetry, WinRM service events और PowerShell operational/script-block logging की अपेक्षा रखें।
- यदि आपको केवल एक command चलानी है, तो `winrs.exe` या one-shot WinRM execution, लंबे समय तक चलने वाले interactive remoting session की तुलना में कम दिखाई दे सकता है।
- यदि Kerberos उपलब्ध है, तो trust संबंधी समस्याओं और client-side `TrustedHosts` में असुविधाजनक बदलावों—दोनों को कम करने के लिए IP + NTLM के बजाय **FQDN + Kerberos** को प्राथमिकता दें।

## References

- [1] [Microsoft: JEA सुरक्षा संबंधी विचार](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: WinRM के ज़रिए PowerShell को remote server से connect करते समय त्रुटि `0x80090322`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
