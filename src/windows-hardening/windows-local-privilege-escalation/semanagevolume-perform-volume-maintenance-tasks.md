# SeManageVolumePrivilege: 임의 파일 읽기를 위한 raw volume access

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows 사용자 권한: 볼륨 유지 관리 작업 수행 (상수: SeManageVolumePrivilege).

이 권한을 보유한 사용자는 조각 모음, 볼륨 생성/제거, 유지 관리 IO와 같은 low-level volume operations를 수행할 수 있습니다. 공격자에게 특히 중요한 점은 이 권한으로 raw volume device handles (예: \\.\C:)을 열고 NTFS file ACL을 우회하는 direct disk I/O를 수행할 수 있다는 것입니다. raw access를 사용하면 DACL에 의해 접근이 거부된 경우에도 볼륨에 있는 모든 파일의 바이트를 복사할 수 있습니다. 이를 위해 파일 시스템 구조를 offline에서 파싱하거나 block/cluster level에서 읽는 도구를 사용할 수 있습니다.

기본값: 서버 및 domain controller의 Administrators.<sup>[[1]](#references)</sup>

## 악용 시나리오

- disk device를 읽어 ACL을 우회한 임의 파일 읽기 (예: %ProgramData%\Microsoft\Crypto\RSA\MachineKeys 및 %ProgramData%\Microsoft\Crypto\Keys에 있는 machine private keys, registry hives, DPAPI masterkeys, SAM, VSS를 통한 ntds.dit 등 민감한 system-protected material 유출).
- raw device에서 바이트를 직접 복사하여 잠겨 있거나 권한이 필요한 경로 (C:\Windows\System32\…) 우회.
- AD CS 환경에서 CA의 key material (machine key store)을 유출하여 “Golden Certificates”를 생성하고 PKINIT를 통해 모든 domain principal을 impersonate. 아래 link를 참조하세요.<sup>[[2]](#references)</sup>

참고: helper tools에 의존하지 않는 한 NTFS 구조를 위한 parser가 여전히 필요합니다. 많은 off-the-shelf tools가 raw access를 추상화합니다.

## 실전 기법

- raw volume handle을 열고 clusters 읽기:

<details>
<summary>확장하려면 클릭</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
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

- NTFS를 인식하는 도구를 사용하여 raw volume에서 특정 파일을 복구합니다:
- RawCopy/RawCopy64 (사용 중인 파일을 sector-level로 복사)
- FTK Imager 또는 The Sleuth Kit (read-only imaging 후 파일 carve)
- vssadmin/diskshadow + shadow copy를 사용한 다음 snapshot에서 대상 파일을 복사합니다 (VSS를 생성할 수 있는 경우; 일반적으로 admin 권한이 필요하지만 SeManageVolumePrivilege를 보유한 동일한 operator가 흔히 사용할 수 있음)

일반적으로 대상으로 삼을 민감한 경로:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controller - shadow copy를 통해)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certificates/CRLs; private keys는 위의 machine key store에 있음)

## AD CS tie-in: Golden Certificate 위조

Enterprise CA의 private key를 machine key store에서 읽을 수 있다면, 임의의 principal을 위한 client-auth certificates를 위조하고 PKINIT/Schannel을 통해 authenticate할 수 있습니다. 이를 흔히 Golden Certificate라고 합니다.<sup>[[2]](#references)</sup> 다음을 참조하세요:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1”).

## Detection 및 hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) 할당을 신뢰할 수 있는 admin으로만 엄격히 제한합니다.
- Sensitive Privilege Use 및 \\.\C:, \\.\PhysicalDrive0과 같은 device object에 대한 process handle opens를 모니터링합니다.
- HSM/TPM-backed CA keys 또는 DPAPI-NG를 우선 사용하여 raw file reads로 key material을 usable form으로 복구할 수 없도록 합니다.
- uploads, temp 및 extraction 경로를 non-executable로 유지하고 서로 분리합니다 (이 chain과 post-exploitation 단계에서 자주 함께 사용하는 web context defense).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
