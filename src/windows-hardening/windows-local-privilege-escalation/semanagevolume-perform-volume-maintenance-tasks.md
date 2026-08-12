# SeManageVolumePrivilege: 볼륨 유지 관리 악용 및 raw-access 검증

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows 사용자 권한: 볼륨 유지 관리 작업 수행(상수: SeManageVolumePrivilege).

이 권한은 조각 모음 및 볼륨 생성 또는 제거와 같은 볼륨 유지 관리 작업을 허용합니다. Microsoft는 이 권한 보유자가 다른 데이터를 포함하는 저장소까지 파일을 확장한 다음, 확보한 바이트를 읽거나 수정할 수 있다고 경고합니다.<sup>[[1]](#references)</sup>

`SeManageVolumePrivilege` 보유를 raw-disk access가 보장된다는 의미로 간주해서는 안 됩니다. Microsoft 문서에 따르면 직접 access를 위해 `CreateFile`을 통해 physical disk 또는 volume을 열려면 administrative privileges가 필요하며, 일반적인 object/device access checks도 계속 적용됩니다. 특정 build 또는 product에서는 arbitrary file read를 주장하기 전에 token, device ACL, requested access, share flags 및 volume state가 raw handle을 허용하는지 테스트해야 합니다.<sup>[[3]](#references)</sup>

기본값: servers 및 domain controllers의 Administrators.<sup>[[1]](#references)</sup>

## Abuse scenarios

- 계정이 실제로 readable raw-volume handle을 획득할 수 있다면, NTFS-aware parser는 per-file ACLs를 우회하여 allocated clusters에서 protected 또는 locked files를 복구할 수 있습니다.
- 가능한 targets에는 `C:\Windows\System32` 아래의 locked 또는 ACL-protected content, registry hives, DPAPI master keys, SAM 및—snapshot 또는 offline volume을 통해 별도로 access할 수 있는 경우—`ntds.dit`가 포함됩니다.
- certificate services hosts에서 유용한 software-key locations에는 `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` 및 `%ProgramData%\Microsoft\Crypto\Keys`가 포함됩니다. 파일을 복구하는 것만으로는 충분하지 않으며, 해당 key material을 export할 수 있고 동시에 decrypt할 수 있어야 합니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- AD CS host에서 성공적으로 복구한 **exportable/software-backed** CA private key는 Golden Certificate abuse를 가능하게 할 수 있습니다. Hardware-backed 또는 non-exportable key designs에서는 이 경로가 달라집니다.<sup>[[2]](#references)</sup>

참고: helper tools에 의존하지 않는 한 NTFS structures를 위한 parser가 여전히 필요합니다. 많은 off-the-shelf tools는 raw access를 추상화합니다.

## Practical techniques

- raw volume handle을 열고 clusters를 읽습니다:

<details>
<summary>Click to expand</summary>
```powershell
# Validation attempt: current Windows versions normally require an administrative token
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
static void Main(string[] a){
using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
fs.Position = 0x100000; // seek
var buf = new byte[4096];
fs.Read(buf,0,buf.Length);
File.WriteAllBytes("C:\\temp\\blk.bin", buf);
}
}
}
```
</details>

- NTFS를 인식하는 tool을 사용해 raw volume에서 특정 파일을 복구합니다:
- RawCopy/RawCopy64 (사용 중인 파일의 sector-level copy)
- FTK Imager 또는 The Sleuth Kit (read-only imaging 후 파일 carve)
- vssadmin/diskshadow + shadow copy를 사용한 다음 snapshot에서 target file을 copy합니다 (VSS를 생성할 수 있는 경우; 일반적으로 admin 권한이 필요하지만, SeManageVolumePrivilege를 보유한 동일한 operator가 흔히 사용할 수 있음)

Target으로 지정할 일반적인 민감한 경로:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – shadow copy를 통해)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys는 위의 machine key store에 저장됨)

## AD CS 연계: Golden Certificate Forging

Enterprise CA의 private key를 machine key store에서 읽을 수 있다면, 임의의 principal에 대한 client-auth certificates를 forge하고 PKINIT/Schannel을 통해 authenticate할 수 있습니다. 이는 흔히 Golden Certificate라고 합니다.<sup>[[2]](#references)</sup> 다음을 참조하세요:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Stolen CA Certificates (Golden Certificate)로 Certificates Forging – DPERSIST1”).

## Detection 및 hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) 할당을 신뢰할 수 있는 admin으로만 엄격히 제한합니다.
- Sensitive Privilege Use와 \\.\C:, \\.\PhysicalDrive0 같은 device objects에 대한 process handle opens를 monitor합니다.
- 적절히 구성된 HSM 또는 TPM-backed, non-exportable CA keys를 우선 사용하여, 복사된 key-container file만으로는 사용 가능한 private-key material을 복구할 수 없도록 합니다.
- CA-key path 외부의 application secrets에는 DPAPI 또는 DPAPI-NG를 사용하면, user, machine, group 또는 기타 authorized principal에 보호되므로 복사된 data file만으로는 충분하지 않게 만들 수 있습니다. 이는 compromised principal이 이미 접근할 수 있는 plaintext를 보호하지는 않습니다.<sup>[[4]](#references)</sup>
- uploads, temp 및 extraction paths를 non-executable로 유지하고 분리합니다 (이 chain post‑exploitation과 함께 사용되는 경우가 많은 web context defense).

## References

- [1] [Microsoft – Volume maintenance tasks 수행 (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (CA key를 읽는 데 SeManageVolumePrivilege 사용 → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation 및 DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
