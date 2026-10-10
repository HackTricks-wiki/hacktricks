# SUSE 세션 및 디스크 서비스 권한 상승 징후

{{#include ../../banners/hacktricks-training.md}}

## PAM을 통한 SSH 세션 인증

CVE-2025-6018은 SSH 인증 스택에서 `pam_env`를 로드한 다음 세션 스택에서 `pam_systemd`를 로드하는 SUSE 15 PAM 구성에 영향을 미쳤습니다. `pam_env`가 사용자의 `.pam_environment`를 읽을 때, 사용자는 SSH 세션이 Polkit에서 물리적으로 활성 상태인 것처럼 보이게 하는 `XDG_SEAT` 및 `XDG_VTNR` 값을 제공할 수 있었습니다. 그러면 `allow_active=yes` 작업을 원격 사용자가 사용할 수 있게 될 수 있었습니다. 이는 세션 인증을 변경하지만, 그 자체로 root 액세스를 보장하지는 않습니다. SUSE는 `pam`의 기본 사용자 환경 동작과 `pam-config`가 생성하는 모듈 배치를 수정했습니다.<sup>[[1]](#references)[[2]](#references)</sup>

유효한 `/etc/pam.d/sshd` include 체인, `pam_env.so`와 `pam_systemd.so`의 순서, 명시적인 `user_readenv=1` 옵션이 있는지 확인하세요. 패치된 `pam` 패키지는 기본 동작을 변경하지만, 명시적인 옵션을 통해 여전히 사용자 환경을 읽도록 요청할 수 있습니다. 최신 `pam-config` 패키지가 설치되어 있다고 해서 로컬에서 수정되었거나 오래된 PAM 스택이 다시 생성되었다는 뜻은 아닙니다. 공급업체 패키지 릴리스와 실제 구성을 함께 확인하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## 활성 사용자 디스크 서비스 경로

CVE-2025-6019는 `udisks2`를 통해 사용되는 `libblockdev`의 권한 상승 경로였습니다. XFS 크기 조정 중 공격자가 제공한 파일 시스템이 예상된 `nosuid` 제한 없이 일시적으로 마운트될 수 있었습니다. 이 경로를 이용하려면 사용 가능한 UDisks D-Bus 서비스, XFS 크기 조정 지원, 호출자가 사용할 수 있는 관련 Polkit 작업, 취약한 라이브러리 패키지가 필요합니다. CVE-2025-6018은 활성 사용자 세션을 확보하는 한 가지 방법이지만, 이미 활성 상태인 사용자라면 별도로 디스크 서비스 경로에 접근할 수 있습니다.<sup>[[3]](#references)</sup>

수동으로 검토할 때는 UDisks 서비스 메타데이터, `org.freedesktop.udisks2.modify-device` 정책, `xfs_growfs`, 설치된 `libbd_fs2` 패키지를 확인하세요. SUSE는 openSUSE Leap 15.6에서 `libbd_fs2` 버전 `2.26-150400.3.5.1`을 수정된 버전으로 명시합니다. 정확한 수정 릴리스는 제품에 따라 다릅니다. 정책과 패키지가 있다는 사실만으로 호출자가 장치를 마운트하거나 크기를 조정할 수 있다고 단정할 수는 없습니다. 열거 중에는 마운트를 변경하거나 D-Bus 메서드를 호출하지 마세요.<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018 권고문](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-config 보안 업데이트](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019 권고문](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
