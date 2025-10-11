# SeManageVolumePrivilege: 임의 파일 읽기를 위한 원시 볼륨 접근

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows 사용자 권한: Perform volume maintenance tasks (상수: SeManageVolumePrivilege).

권한 보유자는 조각모음(defragmentation), 볼륨 생성/삭제, 유지관리 IO와 같은 저수준 볼륨 작업을 수행할 수 있습니다. 공격자에게 특히 중요한 점은 이 권한을 통해 원시 볼륨 디바이스 핸들(예: \\.\C:)을 열고 NTFS file ACLs를 우회하는 직접 디스크 I/O를 실행할 수 있다는 것입니다. 원시 접근으로 파일 시스템 구조를 오프라인에서 파싱하거나 블록/클러스터 수준에서 읽는 도구를 활용하면 DACL에 의해 거부되더라도 해당 볼륨의 어떤 파일 바이트든 복사할 수 있습니다.

기본값: 서버 및 도메인 컨트롤러의 Administrators.

## 남용 시나리오

- 디스크 장치를 읽어 ACL을 우회한 임의 파일 읽기(예: %ProgramData%\Microsoft\Crypto\RSA\MachineKeys 및 %ProgramData%\Microsoft\Crypto\Keys 아래의 머신 개인키, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS 등 민감한 시스템 보호 자료를 exfiltrate).
- 원시 디바이스에서 바이트를 직접 복사하여 잠금/권한이 높은 경로(C:\Windows\System32\…) 우회.
- AD CS 환경에서는 CA의 키 자료(머신 키 저장소)를 탈취하여 "Golden Certificates"를 발행하고 PKINIT를 통해 어떤 도메인 주체로도 가장할 수 있음. 아래 링크 참조.

참고: 헬퍼 도구에 의존하지 않는다면 NTFS 구조를 파싱할 파서가 여전히 필요합니다. 많은 시중 도구가 원시 접근을 추상화합니다.

## 실전 기법

- 원시 볼륨 핸들을 열고 클러스터를 읽기:

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

- Use an NTFS-aware tool to recover specific files from raw volume:
- RawCopy/RawCopy64 (사용 중인 파일의 섹터 단위 복사)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (VSS를 생성할 수 있는 경우; 종종 관리자 권한이 필요하지만 SeManageVolumePrivilege를 가진 운영자들이 흔히 사용할 수 있음)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

If you can read the Enterprise CA’s private key from the machine key store, you can forge client‑auth certificates for arbitrary principals and authenticate via PKINIT/Schannel. This is often referred to as a Golden Certificate. See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(섹션: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## 탐지 및 하드닝

- SeManageVolumePrivilege (Perform volume maintenance tasks)의 할당을 신뢰할 수 있는 관리자에게만 엄격히 제한하세요.
- Sensitive Privilege Use 및 프로세스 핸들로 디바이스 객체(예: \\.\C:, \\.\PhysicalDrive0)에 대한 열기 동작을 모니터링하세요.
- HSM/TPM-backed CA 키 또는 DPAPI-NG를 우선 사용해 원시 파일 읽기로 키 자료를 사용 가능한 형태로 복구할 수 없게 하세요.
- 업로드, 임시, 추출 경로를 실행 불가능(non-executable)하게 유지하고 분리하세요(웹 컨텍스트 방어로, 이 체인에서의 post‑exploitation과 자주 결합됨).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
