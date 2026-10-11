# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM Windows environments में **lateral movement** के लिए सबसे सुविधाजनक transports में से एक है, क्योंकि यह SMB service creation tricks की ज़रूरत के बिना **WS-Man/HTTP(S)** पर remote shell देता है। अगर target पर **5985/5986** उपलब्ध हैं और आपके principal को remoting की अनुमति है, तो आप अक्सर बहुत जल्दी "valid creds" से "interactive shell" तक पहुँच सकते हैं।

**Protocol/service enumeration**, listeners, WinRM enable करने, `Invoke-Command`, और सामान्य client usage के लिए देखें:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Operators को WinRM क्यों पसंद है

- **SMB/RPC** के बजाय **HTTP/HTTPS** का उपयोग करता है, इसलिए अक्सर वहाँ भी काम करता है जहाँ PsExec-style execution blocked होता है।
- **Kerberos** के साथ, यह target को reusable credentials भेजने से बचाता है।
- **Windows**, **Linux**, और **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) से आसानी से काम करता है।
- Interactive PowerShell remoting path, authenticated user context में target पर **`wsmprovhost.exe`** चलाता है, जो service-based exec से operational रूप से अलग है।

## Access model और prerequisites

व्यवहार में, सफल WinRM lateral movement **तीन** चीज़ों पर निर्भर करता है:

1. Target पर **WinRM listener** (`5985`/`5986`) हो और firewall rules access की अनुमति देते हों।
2. Account endpoint पर **authenticate** कर सके।
3. Account को **remoting session खोलने** की अनुमति हो।

यह access पाने के सामान्य तरीके:

- Target पर **Local Administrator** होना।
- नए systems पर **Remote Management Users** का सदस्य होना, या उन systems/components पर **WinRMRemoteWMIUsers__** का सदस्य होना जो अब भी उस group को मान्यता देते हैं।
- Local security descriptors / PowerShell remoting ACL changes के ज़रिए स्पष्ट remoting rights सौंपे गए हों।

अगर आप पहले से admin rights वाले box को control करते हैं, तो याद रखें कि यहाँ बताई गई techniques का उपयोग करके **full admin group membership के बिना भी WinRM access delegate** किया जा सकता है:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement के दौरान ध्यान रखने योग्य authentication gotchas

- **Kerberos के लिए hostname/FQDN ज़रूरी है**। अगर आप IP से connect करते हैं, तो client आमतौर पर **NTLM/Negotiate** पर fallback करता है।
- **Workgroup** या cross-trust edge cases में, NTLM के लिए आमतौर पर **HTTPS** या client पर target को **TrustedHosts** में जोड़ना ज़रूरी होता है।
- Workgroup में Negotiate के ज़रिए **local accounts** का उपयोग करने पर, UAC remote restrictions access रोक सकती हैं—जब तक कि built-in Administrator account का उपयोग न किया जाए या `LocalAccountTokenFilterPolicy=1` सेट न हो।
- PowerShell remoting में default रूप से **`HTTP/<host>` SPN** इस्तेमाल होता है। जिन environments में **`HTTP/<host>`** पहले से किसी दूसरे service account के लिए registered है, वहाँ WinRM Kerberos `0x80090322` के साथ fail हो सकता है; port-qualified SPN का उपयोग करें या **`WSMAN/<host>`** पर switch करें, जहाँ वह SPN मौजूद हो।<sup>[[3]](#references)</sup>

अगर password spraying के दौरान आपको valid credentials मिलते हैं, तो WinRM से उन्हें validate करना अक्सर यह जाँचने का सबसे तेज़ तरीका होता है कि उनसे shell मिल सकती है या नहीं:

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

### इंटरैक्टिव shells के लिए Evil-WinRM

Linux से इंटरैक्टिव उपयोग के लिए `evil-winrm` अब भी सबसे सुविधाजनक विकल्प है, क्योंकि यह **पासवर्ड**, **NT hashes**, **Kerberos tickets**, **client certificates**, file transfer और in-memory PowerShell/.NET loading को सपोर्ट करता है।

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

जब डिफ़ॉल्ट **`HTTP/<host>`** SPN के कारण Kerberos विफल हो, तो इसके बजाय **`WSMAN/<host>`** ticket का अनुरोध करने/उसे इस्तेमाल करने की कोशिश करें। ऐसा hardened या असामान्य enterprise setups में देखने को मिलता है, जहाँ `HTTP/<host>` पहले से किसी अन्य service account से जुड़ा होता है।<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

यह **RBCD / S4U** abuse के बाद भी उपयोगी है, जब आपने सामान्य `HTTP` ticket के बजाय खास तौर पर **WSMAN** service ticket forge किया हो या request किया हो।

### Certificate-based authentication

WinRM **client certificate authentication** को भी support करता है, लेकिन certificate को target पर किसी **local account** से map किया जाना चाहिए। Offensive perspective से यह तब महत्वपूर्ण होता है, जब:

- आपने WinRM के लिए पहले से mapped valid client certificate और private key चुराई या export की हो;
- आपने **AD CS / Pass-the-Certificate** abuse करके किसी principal के लिए certificate प्राप्त किया हो और फिर किसी दूसरे authentication path में pivot किया हो;
- आप ऐसे environments में काम कर रहे हों जो जानबूझकर password-based remoting से बचते हैं।

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM, password/hash/Kerberos auth की तुलना में बहुत कम आम है, लेकिन मौजूद होने पर यह **passwordless lateral movement** का ऐसा रास्ता दे सकता है जो password rotation के बाद भी काम करता है।

### `pypsrp` के साथ Python / automation

अगर आपको operator shell के बजाय automation चाहिए, तो `pypsrp` Python से WinRM/PSRP उपलब्ध कराता है और **NTLM**, **certificate auth**, **Kerberos**, और **CredSSP** को support करता है।<sup>[[2]](#references)</sup>

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


यदि आपको high-level `Client` wrapper से अधिक सूक्ष्म नियंत्रण चाहिए, तो निचले-स्तर के `WSMan` + `RunspacePool` APIs दो आम operator समस्याओं के लिए उपयोगी हैं:

- कई PowerShell clients द्वारा अपेक्षित default `HTTP` के बजाय Kerberos service/SPN के रूप में **`WSMAN`** का उपयोग करना;
- `Microsoft.PowerShell` के बजाय किसी **JEA** / custom session configuration जैसे **non-default PSRP endpoint** से कनेक्ट करना।

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

### Lateral movement के दौरान custom PSRP endpoints और JEA महत्वपूर्ण हैं

सफल WinRM authentication का **यह अर्थ हमेशा नहीं होता** कि आपको default unrestricted `Microsoft.PowerShell` endpoint मिलता है। परिपक्व environments में **custom session configurations** या **JEA** endpoints उपलब्ध हो सकते हैं, जिनके अपने ACLs और run-as behavior होते हैं।<sup>[[1]](#references)</sup>

अगर आपके पास पहले से किसी Windows host पर code execution है और आप यह समझना चाहते हैं कि कौन-से remoting surfaces मौजूद हैं, तो registered endpoints enumerate करें:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

जब कोई उपयोगी endpoint मौजूद हो, तो default shell के बजाय उसे स्पष्ट रूप से target करें:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

व्यावहारिक offensive निहितार्थ:

- **restricted** endpoint भी lateral movement के लिए पर्याप्त हो सकता है, यदि उसमें service control, file access, process creation या मनमाने .NET / external command execution के लिए सही cmdlets/functions उपलब्ध हों।
- **misconfigured JEA** role विशेष रूप से उपयोगी होता है, जब उसमें `Start-Process`, व्यापक wildcards, writable providers या custom proxy functions जैसे खतरनाक commands हों, जिनसे intended restrictions से बाहर निकला जा सके।
- **RunAs virtual accounts** या **gMSAs** से जुड़े endpoints आपके द्वारा चलाए जाने वाले commands का effective security context बदल देते हैं। खास तौर पर, gMSA-backed endpoint **second hop पर network identity** दे सकता है, भले ही सामान्य WinRM session में classic delegation problem आए।

Custom restricted endpoint के लिए, उसकी effective command और script permissions का अलग-अलग निरीक्षण करें: `Get-Command` की छोटी सूची अकेले यह साबित नहीं करती कि कोई मौजूदा `.ps1` नहीं चल सकती। [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) स्पष्ट रूप से नियंत्रित करती हैं कि किन script paths को invoke किया जा सकता है; अन्य custom endpoints अलग session rules लागू कर सकते हैं। यदि किसी अनुमत script में दूसरे host के लिए credential बनाने हेतु stored `SecureString` का उपयोग होता है, तो explicit key के बिना बनाई गई blob [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) का उपयोग करती है और decryption के लिए आम तौर पर उसे protect करने वाले user और machine context की ज़रूरत होती है। Writable source या copied blob को cross-host escalation path मानने से पहले script का ACL, अनुमत invocation, run-as identity और downstream credential rights जाँचें। Passive enumeration के दौरान protected value प्रिंट न करें।

File path स्वीकार करने वाले JEA custom function के लिए, registered endpoint ACL, mapped role capability और effective run-as identity—तीनों को साथ में जाँचें। Caller के पास `NoLanguage` हो सकता है, जबकि function body system के default language mode में चलती है; virtual account के पास local administrator rights भी हो सकते हैं। यदि function raw string prefix से allowed directory जाँचती है और बाद में दिए गए path को पढ़ती है, तो `..` components उस directory के बाहर resolve हो सकते हैं। सीमा function की identity के तहत resolved path है, न कि caller का language mode या दिखने वाला prefix। किसी readable `.psrc` या `.pssc` file को privileged file-read finding मानने से पहले reachable function और उसकी final-path validation की पुष्टि करें। Microsoft की [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) और [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations) guidance देखें।

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` built in है और **native WinRM command execution** के लिए उपयोगी है, जब आप interactive PowerShell remoting session खोले बिना commands चलाना चाहते हैं:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

दो flags को भूलना आसान है, लेकिन व्यवहार में वे मायने रखते हैं:

- `/noprofile` की अक्सर ज़रूरत होती है, जब remote principal **local administrator** न हो।
- `/allowdelegate` remote shell को **तीसरे host** के विरुद्ध आपके credentials इस्तेमाल करने देता है (उदाहरण के लिए, जब command को `\\fileserver\share` की ज़रूरत हो)।

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

व्यवहार में, `winrs.exe` से अक्सर इसी तरह की remote process chain बनती है:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

यह याद रखने योग्य है, क्योंकि यह service-based exec और interactive PSRP sessions से अलग है।

### `winrm.cmd` / PowerShell remoting के बजाय WS-Man COM

आप `Enter-PSSession` के बिना भी WS-Man के ज़रिए WMI classes को invoke करके **WinRM transport** के माध्यम से execute कर सकते हैं। इससे transport WinRM ही रहता है, जबकि remote execution primitive **WMI `Win32_Process.Create`** बन जाता है:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

यह तरीका तब उपयोगी है, जब:

- PowerShell logging की कड़ी निगरानी की जाती है।
- आप **WinRM transport** चाहते हैं, लेकिन क्लासिक PS remoting workflow नहीं।
- आप **`WSMan.Automation`** COM object के आसपास custom tooling बना रहे हैं या उसका उपयोग कर रहे हैं।

## NTLM relay to WinRM (WS-Man)

जब signing के कारण SMB relay अवरुद्ध हो और LDAP relay पर पाबंदियाँ हों, तब भी **WS-Man/WinRM** एक आकर्षक relay target हो सकता है। आधुनिक `ntlmrelayx.py` में **WinRM relay servers** शामिल हैं और यह **`wsman://`** या **`winrms://`** targets पर relay कर सकता है।

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

दो व्यावहारिक बातें:

- Relay तब सबसे उपयोगी होता है, जब target **NTLM** स्वीकार करता हो और relayed principal को WinRM इस्तेमाल करने की अनुमति हो।
- हाल के Impacket code में **`WSMANIDENTIFY: unauthenticated`** requests को विशेष रूप से संभाला जाता है, ताकि `Test-WSman`-style probes relay flow को बाधित न करें।

पहला WinRM session मिलने के बाद multi-hop से जुड़ी सीमाओं के लिए देखें:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC और detection संबंधी नोट्स

- **Interactive PowerShell remoting** आम तौर पर target पर **`wsmprovhost.exe`** बनाता है।
- **`winrs.exe`** आम तौर पर **`winrshost.exe`** बनाता है और फिर अनुरोधित child process चलाता है।
- Custom **JEA** endpoints, actions को **`WinRM_VA_*`** virtual accounts या configured **gMSA** के रूप में चला सकते हैं। इससे telemetry और second-hop व्यवहार, सामान्य user-context shell की तुलना में बदल जाता है।<sup>[[1]](#references)</sup>
- अगर आप raw `cmd.exe` के बजाय PSRP इस्तेमाल करते हैं, तो network logon telemetry, WinRM service events और PowerShell operational/script-block logging की अपेक्षा करें।
- अगर आपको सिर्फ़ एक command चलानी है, तो `winrs.exe` या one-shot WinRM execution, लंबे समय तक चलने वाले interactive remoting session की तुलना में कम दिखाई दे सकता है।
- अगर Kerberos उपलब्ध है, तो trust संबंधी समस्याएँ और client-side `TrustedHosts` में असुविधाजनक बदलाव—दोनों कम करने के लिए IP + NTLM के बजाय **FQDN + Kerberos** को प्राथमिकता दें।

## References

- [1] [Microsoft: JEA सुरक्षा संबंधी विचार](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: WinRM के ज़रिए PowerShell को remote server से जोड़ते समय त्रुटि `0x80090322`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
