# SeManageVolumePrivilege: 볼륨 유지 관리 악용 및 raw-access 검증

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows 사용자 권한: 볼륨 유지 관리 작업 수행(상수: SeManageVolumePrivilege).

이 권한은 볼륨 조각 모음, 볼륨 생성 또는 제거와 같은 볼륨 유지 관리 작업을 허용합니다. Microsoft는 이 권한을 가진 사용자가 다른 데이터가 들어 있는 저장 공간까지 파일을 확장한 다음, 확보한 바이트를 읽거나 수정할 수 있다고 경고합니다.<sup>[[1]](#references)</sup>

`SeManageVolumePrivilege`를 보유했다고 해서 raw-disk access가 보장되는 것은 아닙니다. Microsoft 문서에 따르면 직접 액세스를 위해 `CreateFile`로 물리 디스크나 볼륨을 열려면 관리자 권한이 필요하며, 일반적인 개체/장치 액세스 검사도 계속 적용됩니다. 특정 빌드나 제품에서 임의의 파일을 읽을 수 있다고 주장하기 전에 토큰, 장치 ACL, 요청한 액세스 권한, 공유 플래그 및 볼륨 상태가 raw handle 획득을 허용하는지 테스트하세요.<sup>[[3]](#references)</sup>

기본값: 서버 및 도메인 컨트롤러의 Administrators.<sup>[[1]](#references)</sup>

## 악용 시나리오

- 계정이 실제로 읽기 가능한 raw-volume handle을 획득할 수 있다면, NTFS를 인식하는 parser를 사용해 파일별 ACL을 우회하고 할당된 클러스터에서 보호되거나 잠긴 파일을 복구할 수 있습니다.
- 가능한 대상에는 `C:\Windows\System32`의 잠긴 파일 또는 ACL로 보호된 콘텐츠, 레지스트리 하이브, DPAPI master key, SAM, 그리고 스냅샷이나 오프라인 볼륨을 통해 별도로 액세스할 수 있는 경우의 `ntds.dit`가 포함됩니다.
- 인증서 서비스 호스트에서 유용한 software-key 위치는 `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` 및 `%ProgramData%\Microsoft\Crypto\Keys`입니다. 파일을 복구하는 것만으로는 충분하지 않으며, 키 자료를 내보낼 수 있고 복호화할 수도 있어야 합니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- AD CS 호스트에서 **내보낼 수 있는/software-backed** CA private key를 성공적으로 복구하면 Golden Certificate 악용이 가능해질 수 있습니다. Hardware-backed 또는 non-exportable 키 설계를 사용하면 이 경로가 달라집니다.<sup>[[2]](#references)</sup>
- 일부 볼륨 유지 관리 도구는 해당 작업이 허용될 때 `FSCTL_SD_GLOBAL_CHANGE`를 사용해 파일시스템 ACL 항목을 대체합니다. 이는 raw block을 수동적으로 읽는 대신 액세스 제어를 변경하며, 볼륨의 넓은 영역에 영향을 줄 수 있으므로 실제 토큰 및 장치 동작을 기준으로 검증해야 합니다. [tool source](https://github.com/CsEnox/SeManageVolumeExploit)는 이 특정 메커니즘을 보여 줍니다. 권한을 보유했다는 사실만으로 성공이 입증되지는 않습니다.
- ACL 변경을 통해 파일에 액세스할 수 있게 되더라도 EFS로 암호화된 파일이 복호화되는 것은 아닙니다. 평문을 얻으려면 해당 사용자 또는 복구용 private key가 필요합니다. 마찬가지로 [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)를 사용해 software-backed CA key를 내보내려면 해당 키가 로컬에서 사용 가능하고, 내보낼 수 있으며, 액세스 가능해야 합니다.

참고: 보조 도구에 의존하지 않는 한 NTFS 구조를 처리할 parser가 여전히 필요합니다. 대부분의 기성 도구는 raw access를 추상화합니다.

## 실용적인 기법

- raw volume handle을 열고 클러스터를 읽습니다:

<details>
<summary>확장하려면 클릭</summary>

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

- Raw volume에서 특정 파일을 복구하려면 NTFS를 인식하는 도구를 사용합니다.
  - RawCopy/RawCopy64 (사용 중인 파일의 섹터 수준 복사)
  - FTK Imager 또는 The Sleuth Kit (읽기 전용 이미징 후 파일 카빙)
  - vssadmin/diskshadow + shadow copy를 사용한 다음 스냅샷에서 대상 파일 복사 (VSS를 생성할 수 있는 경우. 대개 관리자 권한이 필요하지만, SeManageVolumePrivilege를 보유한 동일한 operator가 사용할 수 있는 경우가 많음)

일반적인 민감 경로:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (로컬 secrets)
- C:\Windows\NTDS\ntds.dit (도메인 컨트롤러 – shadow copy 사용)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA 인증서/CRL; private key는 위의 machine key store에 저장됨)

## AD CS 연계: Golden Certificate 위조

Enterprise CA의 private key를 machine key store에서 읽을 수 있다면, 임의의 principal을 위한 client-auth 인증서를 위조하고 PKINIT/Schannel을 통해 인증할 수 있습니다. 이를 흔히 Golden Certificate라고 합니다.<sup>[[2]](#references)</sup> 참고:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(섹션: “탈취한 CA 인증서로 인증서 위조 (Golden Certificate) – DPERSIST1”).

## 탐지 및 하드닝

- SeManageVolumePrivilege (볼륨 유지 관리 작업 수행) 할당을 신뢰할 수 있는 관리자에게만 엄격히 제한합니다.
- Sensitive Privilege Use 및 \\.\C:, \\.\PhysicalDrive0 같은 device object에 대한 프로세스 핸들 열기를 모니터링합니다.
- 복사한 key-container 파일만으로 사용 가능한 private-key material을 복구할 수 없도록, 적절히 구성된 HSM 또는 TPM 기반의 내보내기 불가능한 CA key를 우선 사용합니다.
- CA key 경로 외부의 애플리케이션 secrets에는 DPAPI 또는 DPAPI-NG를 사용할 수 있습니다. 이를 통해 데이터 파일을 복사하는 것만으로는 충분하지 않도록, 파일을 사용자, 머신, 그룹 또는 다른 권한이 부여된 principal에 연결해 보호할 수 있습니다. 이는 침해된 principal이 이미 접근할 수 있는 평문을 보호하지는 않습니다.<sup>[[4]](#references)</sup>
- 업로드, 임시 파일 및 추출 경로는 실행 불가능한 상태로 유지하고 서로 분리합니다 (이 공격 체인 이후 단계에서 자주 함께 적용되는 웹 컨텍스트 방어).

## References

- [1] [Microsoft – 볼륨 유지 관리 작업 수행 (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege로 CA key 읽기 → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` 물리 디스크 및 볼륨](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation 및 DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
