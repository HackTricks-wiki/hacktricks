# AD CS 인증서 탈취

{{#include ../../../banners/hacktricks-training.md}}

**[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)의 훌륭한 연구 중 Theft 챕터를 간략하게 요약한 내용입니다.**<sup>[[1]](#references)</sup>

## 인증서로 무엇을 할 수 있나요

인증서를 탈취하는 방법을 확인하기 전에, 해당 인증서가 어떤 용도로 유용한지 알아보는 방법에 대한 정보를 소개합니다:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Crypto APIs를 사용한 인증서 Export – THEFT1

**interactive desktop session**에서 사용자 또는 머신 인증서와 private key를 추출하는 작업은, 특히 **private key가 export 가능**한 경우 쉽게 수행할 수 있습니다. `certmgr.msc`에서 인증서로 이동한 후 마우스 오른쪽 버튼을 클릭하고 `All Tasks → Export`를 선택하면 password로 보호되는 .pfx 파일을 생성할 수 있습니다.<sup>[[1]](#references)</sup>

**programmatic approach**로는 PowerShell의 `ExportPfxCertificate` cmdlet이나 [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer)와 같은 프로젝트를 사용할 수 있습니다. 이러한 도구는 **Microsoft CryptoAPI**(CAPI) 또는 Cryptography API: Next Generation (CNG)을 사용해 certificate store와 상호 작용합니다. 이러한 API는 인증서 저장 및 authentication에 필요한 기능을 포함하여 다양한 cryptographic service를 제공합니다.

그러나 private key가 non-exportable로 설정된 경우 CAPI와 CNG 모두 일반적으로 해당 인증서의 추출을 차단합니다. 이 제한을 우회하려면 **Mimikatz**와 같은 도구를 사용할 수 있습니다. Mimikatz는 각 API를 patch하여 private key를 export할 수 있도록 `crypto::capi` 및 `crypto::cng` 명령을 제공합니다. 구체적으로 `crypto::capi`는 현재 process 내의 CAPI를 patch하고, `crypto::cng`는 **lsass.exe**의 memory를 대상으로 patch합니다.

## DPAPI를 통한 User Certificate Theft – THEFT2

DPAPI에 대한 자세한 정보:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Windows에서 **certificate private key는 DPAPI로 보호됩니다**. **user 및 machine private key의 storage location**은 서로 다르며, file structure도 운영 체제에서 사용하는 cryptographic API에 따라 달라진다는 점을 인지해야 합니다. **SharpDPAPI**는 DPAPI blob을 decrypt할 때 이러한 차이를 자동으로 처리할 수 있는 도구입니다.<sup>[[1]](#references)</sup>

**User certificate**는 주로 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` registry에 저장되지만, 일부는 `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` directory에서도 찾을 수 있습니다. 이러한 certificate에 해당하는 **private key**는 일반적으로 **CAPI** key의 경우 `%APPDATA%\Microsoft\Crypto\RSA\User SID\`에, **CNG** key의 경우 `%APPDATA%\Microsoft\Crypto\Keys\`에 저장됩니다.

**certificate와 연결된 private key를 추출**하는 과정은 다음과 같습니다.

1. user store에서 **target certificate를 선택**하고 해당 key store name을 가져옵니다.
2. 연결된 private key를 decrypt하는 데 필요한 **DPAPI masterkey를 찾습니다**.
3. plaintext DPAPI masterkey를 사용하여 **private key를 decrypt합니다**.

**plaintext DPAPI masterkey를 획득**하는 방법은 다음과 같습니다:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
masterkey 파일과 private key 파일의 복호화를 간소화하려면 [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)의 `certificates` command가 유용합니다. `/pvk`, `/mkfile`, `/password` 또는 `{GUID}:KEY`를 인자로 받아 private key와 연결된 certificate를 복호화한 후 `.pem` 파일을 생성합니다.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## DPAPI를 통한 Machine Certificate Theft – THEFT3

Windows가 레지스트리의 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`에 저장하는 Machine certificates와, `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`(CAPI용) 및 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`(CNG용)에 저장된 관련 private keys는 machine의 DPAPI master keys를 사용해 암호화됩니다. 이러한 keys는 domain의 DPAPI backup key로 복호화할 수 없으며, SYSTEM user만 액세스할 수 있는 **DPAPI_SYSTEM LSA secret**이 필요합니다.<sup>[[1]](#references)</sup>

**Mimikatz**에서 `lsadump::secrets` command를 실행하여 DPAPI_SYSTEM LSA secret을 추출한 다음, 이 key를 사용해 machine masterkeys를 복호화하면 수동 복호화를 수행할 수 있습니다. 또는 앞서 설명한 것처럼 CAPI/CNG를 patch한 후 Mimikatz의 `crypto::certificates /export /systemstore:LOCAL_MACHINE` command를 사용할 수 있습니다.

**SharpDPAPI**는 certificates command를 통해 보다 자동화된 방법을 제공합니다. elevated permissions으로 `/machine` flag를 사용하면 SYSTEM으로 권한을 상승시키고, DPAPI_SYSTEM LSA secret을 dump한 후 이를 사용해 machine DPAPI masterkeys를 복호화합니다. 그런 다음 이 plaintext keys를 lookup table로 사용하여 모든 machine certificate private keys를 복호화합니다.

## Certificate Files 찾기 – THEFT4

Certificates는 file shares나 Downloads folder 등 filesystem에서 직접 발견되는 경우가 있습니다. Windows 환경을 대상으로 하는 certificate files 중 가장 흔히 발견되는 유형은 `.pfx` 및 `.p12` files입니다. 빈도는 낮지만 `.pkcs12` 및 `.pem` extensions를 가진 files도 나타납니다. 주목할 만한 추가 certificate 관련 file extensions는 다음과 같습니다.<sup>[[1]](#references)</sup>

- private keys용 `.key`,
- certificates만 포함하는 `.crt`/`.cer`,
- certificates 또는 private keys를 포함하지 않는 Certificate Signing Requests용 `.csr`,
- Java applications에서 사용하는 certificates와 private keys를 함께 보관할 수 있는 Java Keystores용 `.jks`/`.keystore`/`.keys`.

이러한 files는 언급된 extensions를 검색하여 PowerShell 또는 command prompt를 사용해 찾을 수 있습니다.

PKCS#12 certificate file이 발견되었고 password로 보호되어 있는 경우, [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html)에서 제공되는 `pfx2john.py`를 사용하여 hash를 추출할 수 있습니다. 이후 JohnTheRipper를 사용해 password cracking을 시도할 수 있습니다.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## PKINIT를 통한 NTLM Credential Theft – THEFT5 (UnPAC the hash)

제공된 내용에서는 THEFT5로 분류된 theft method를 통해 PKINIT로 NTLM credential을 theft하는 방법을 설명합니다. 다음은 해당 내용을 수동태로 재설명하고, 필요한 경우 내용을 익명화하고 요약한 것입니다.<sup>[[1]](#references)</sup>

Kerberos authentication을 지원하지 않는 애플리케이션에서 NTLM authentication `MS-NLMP`를 지원하기 위해, PKCA가 사용되면 KDC는 privilege attribute certificate (PAC) 내부, 특히 `PAC_CREDENTIAL_INFO` buffer에 사용자의 NTLM one-way function (OWF)을 반환하도록 설계되어 있습니다. 따라서 계정이 PKINIT를 통해 authentication하고 Ticket-Granting Ticket (TGT)을 획득하면, legacy authentication protocol을 유지하기 위해 현재 host가 TGT에서 NTLM hash를 추출할 수 있는 mechanism이 기본적으로 제공됩니다. 이 과정에서는 본질적으로 NTLM plaintext를 NDR serialized 형태로 나타낸 `PAC_CREDENTIAL_DATA` structure가 복호화됩니다.

[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo)에서 사용할 수 있는 utility **Kekeo**는 이 specific data가 포함된 TGT를 요청하여 사용자의 NTLM을 retrieve할 수 있는 것으로 언급됩니다. 이를 위해 사용되는 command는 다음과 같습니다:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`**는 **`asktgt [...] /getcredentials`** 옵션을 사용하여 이 정보를 가져올 수도 있습니다.

또한 PIN을 가져올 수 있다면 Kekeo가 smartcard로 보호된 인증서를 처리할 수 있는 것으로 알려져 있으며, [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe)가 참고 자료로 언급됩니다. 동일한 기능이 [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)에서 제공되는 **Rubeus**에서도 지원되는 것으로 나타나 있습니다.

이 설명은 PKINIT를 통한 NTLM credential theft에 관련된 프로세스와 도구를 정리한 것으로, PKINIT를 사용하여 획득한 TGT를 통해 NTLM hash를 가져오는 과정과 이를 지원하는 utility에 중점을 둡니다.

## References

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
