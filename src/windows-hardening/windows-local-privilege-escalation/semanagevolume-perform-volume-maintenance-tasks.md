# SeManageVolumePrivilege: 임의 파일 읽기를 위한 원시 볼륨 액세스

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows 사용자 권한: 볼륨 유지 관리 작업 수행 (상수: SeManageVolumePrivilege).

권한 보유자는 조각 모음, 볼륨 생성/제거, 유지 관리 IO와 같은 저수준 볼륨 작업을 수행할 수 있습니다. 공격자에게 특히 중요한 점은 이 권한으로 원시 볼륨 장치 핸들(예: \\.\C:)을 열고 NTFS 파일 ACL을 우회하는 직접 디스크 I/O를 실행할 수 있다는 것입니다. 원시 액세스를 통해 파일 시스템 구조를 오프라인으로 파싱하거나 블록/클러스터 수준에서 읽는 도구를 활용하여 DACL에 의해 접근이 거부된 경우에도 볼륨 상의 어떤 파일이든 바이트 단위로 복사할 수 있습니다.

기본: 서버 및 도메인 컨트롤러의 Administrators.

## 악용 시나리오

- 디스크 장치를 읽어 ACL을 우회한 임의 파일 읽기(예: %ProgramData%\Microsoft\Crypto\RSA\MachineKeys 및 %ProgramData%\Microsoft\Crypto\Keys 아래의 머신 개인키, 레지스트리 하이브, DPAPI 마스터키, SAM, VSS를 통한 ntds.dit 등 민감한 시스템 보호 자료 탈취).
- raw device에서 바이트를 직접 복사하여 잠긴/권한 있는 경로(C:\Windows\System32\…) 우회.
- AD CS 환경에서 CA의 키 자료(머신 키 스토어)를 탈취해 “Golden Certificates”를 발급하고 PKINIT를 통해 어떤 도메인 주체도 가장(impersonate)할 수 있음. 아래 링크 참조.

참고: 보조 도구에 의존하지 않는 한 NTFS 구조를 파싱할 파서가 여전히 필요합니다. 상용 도구 중 다수는 원시 액세스를 추상화합니다.

## 실전 기법

- 원시 볼륨 핸들을 열고 클러스터를 읽기:

<details>
<summary>Click to expand</summary>
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
- RawCopy/RawCopy64 (사용 중인 파일의 섹터 수준 복사)
- FTK Imager or The Sleuth Kit (읽기 전용 이미징, 이후 파일 카빙)
- vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (VSS를 생성할 수 있다면; 종종 관리자 권한이 필요하지만 SeManageVolumePrivilege를 가진 동일한 운영자에게 흔히 제공됨)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (로컬 비밀)
- C:\Windows\NTDS\ntds.dit (도메인 컨트롤러 – shadow copy를 통해)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; 개인 키는 위의 machine key store에 저장됨)

## AD CS tie‑in: Forging a Golden Certificate

만약 machine key store에서 Enterprise CA의 개인 키를 읽을 수 있다면, 임의의 주체에 대해 client‑auth 인증서를 위조하고 PKINIT/Schannel을 통해 인증할 수 있습니다. 이는 흔히 Golden Certificate라고 합니다. 참고:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(섹션: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks)의 할당을 신뢰할 수 있는 관리자에게만 엄격히 제한하십시오.
- Sensitive Privilege Use와 \\.\C:, \\.\PhysicalDrive0 같은 디바이스 객체에 대한 프로세스 핸들 오픈을 모니터링하십시오.
- 원시 파일 읽기로부터 키 자료가 사용 가능한 형태로 복구되지 않도록 HSM/TPM 기반 CA 키 또는 DPAPI-NG를 우선 사용하십시오.
- 업로드, 임시 및 추출 경로를 실행 불가능(non-executable)하고 분리된 상태로 유지하십시오(웹 컨텍스트 방어로서 이 체인 후-악용과 자주 결합됨).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
