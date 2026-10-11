# 심볼릭 링크, 하드링크, 파일 디스크립터

{{#include ../../banners/hacktricks-training.md}}

경로는 해석되는 시점의 객체를 가리키지만, 열린 파일 디스크립터는 경로명이 바뀐 뒤에도 객체에 대한 참조를 유지합니다. 이러한 차이로 심볼릭 링크 race, 숨겨진 하드링크, 삭제된 파일 복구, 상속된 디스크립터 leak이 발생할 수 있습니다. inode와 마운트에 관한 배경 정보는 [파일시스템, inode 및 복구](filesystem-inodes-and-recovery.md)를 참고하세요.

## 링크 및 경로 소유권 검사

```bash
namei -l /path/to/privileged/input
stat -c '%D %i %h %U:%G %a %n' /path/to/file
readlink -f /path/to/link
find /path/to/tree -type l -ls 2>/dev/null
find /path/to/tree -type f -links +1 -ls 2>/dev/null
```

심볼릭 링크(symlink)는 경로명 해석을 다른 곳으로 리디렉션하고, 하드 링크(hardlink)는 같은 파일시스템의 동일한 inode를 가리키는 또 다른 이름입니다. 권한이 높은 작업이 사용자가 쓰기 가능한 디렉터리 안의 예측 가능한 경로를 읽거나 쓰면, 사용자가 해당 경로를 민감한 대상으로 리디렉션할 수 있습니다. 최종 파일뿐 아니라 모든 상위 디렉터리의 소유권과 권한을 확인하세요. `fs.protected_symlinks`와 `fs.protected_hardlinks`는 일반적인 사용자 간 공격을 줄여 주지만, 임의의 쓰기 가능 경로를 안전하게 만들어 주지는 않습니다.

권한이 높은 작업이 셸 글로브로 권한을 변경한다면, **명령줄 피연산자**로 확장된 링크와 이후 재귀 순회 중 발견된 링크를 구분해야 합니다. [GNU `chmod`는 명령줄에 지정된 심볼릭 링크의 참조 대상을 처리합니다](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html). 반면 재귀 순회 중 발견된 심볼릭 링크는 보통 무시합니다. `-R`만으로는 두 경우가 같아지지 않습니다. 예약된 작업의 실제 실행 사용자와 명령, 신뢰할 수 없는 사용자가 글로브에 일치하는 항목을 만들 수 있는지, 설치된 `chmod`의 동작과 옵션, 제안된 대상의 변경 후 접근 권한을 검토하세요. 디렉터리가 쓰기 가능하거나 심볼릭 링크가 있다는 사실만으로 권한 상승이 성립하지는 않습니다. 수동 열거 중에는 링크를 만들거나 작업을 트리거하지 말고 스크립트와 경로 메타데이터를 확인하세요.

권한이 높은 예약 작업은 파일명에 무작위처럼 보이는 해시가 들어가더라도 출력 경로를 예측 가능하게 만들 수 있습니다. [C `rand()`는 동일한 `srand()` 시드에서 같은 시퀀스를 반복합니다](https://man7.org/linux/man-pages/man3/rand.3.html). 여기에는 알려진 실행 시각에서 파생된 시드도 포함됩니다. 작업이 이름을 만들 때 호출자가 쓰기 가능한 데이터베이스 행도 읽는다면, 정확한 행-이름 생성 알고리즘, 시드와 libc 동작, 실행 일정, 호출자의 행 쓰기 및 디렉터리 생성 권한, 권한이 높은 프로세스가 파일을 열기 전에 기존 심볼릭 링크를 배치할 수 있는지 확인하세요. [`fopen(..., "w")`는 해석된 파일을 생성하거나 내용을 잘라냅니다](https://man7.org/linux/man-pages/man3/fopen.3.html). 링크 공격을 방지하는 open 플래그나 원자적 교체를 사용하는지, 유효한 쓰기 권한의 주체, 대상 권한, sticky 디렉터리의 심볼릭 링크 정책을 실제 구현에서 확인하세요. 예측 가능한 이름이나 쓰기 가능한 행만으로는 검토를 시작할 근거일 뿐입니다. 수동 열거 중에는 행을 추가하거나 작업을 실행하지 말고 코드, 일정, 메타데이터를 확인하세요.

다른 사용자 권한으로 실행되는 파일 변환 서비스에서는 호출자가 출력 경로나 확장자를 선택할 수 있는지, 변환기가 기존 출력 심볼릭 링크를 따라가는지 검토하세요. 일부 변환기는 경로명의 확장자로 출력 형식을 선택합니다. 허용된 확장자를 가진 이름의 링크도 확장자가 없는 민감한 대상을 가리킬 수 있습니다. 사용자 간 쓰기 공격이 성립하려면 접근 가능한 서비스, 호출자가 제어하는 경로와 링크, 출력용으로 링크를 여는 변환기, 서비스 실행 사용자의 쓰기 권한이 모두 필요합니다. Linux의 `fs.protected_symlinks=1`은 **sticky가 설정된 모든 사용자 쓰기 가능 디렉터리**에서 다른 사용자의 링크를 따라가는 것을 제한합니다. 일반적인 사용자 소유 디렉터리의 링크에는 같은 보호를 제공하지 않습니다. 결론을 내리기 전에 해석된 경로와 상위 디렉터리의 소유권을 확인하세요. [calibre의 출력 파일 동작](https://manual.calibre-ebook.com/generated/en/ebook-convert.html)과 [Linux 심볼릭 링크 정책](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks)을 참고하세요.

sudo 실행이 허용된 다운로드 래퍼가 호출자가 선택한 데이터를 가져오면서 호출자 제어 작업 디렉터리를 유지한다면, 출력 경로도 같은 방식으로 검토해야 합니다. 실제 다운로드 프로그램과 선택된 기본 파일명, 파일명 충돌 처리 또는 기존 심볼릭 링크가 권한이 높은 쓰기를 다른 곳으로 리디렉션할 수 있는지 확인하세요. URL 선택이나 심볼릭 링크만으로는 충분하지 않습니다. [Axel은 사용자별 `~/.axelrc`를 문서화하고 있으며](https://github.com/axel-download-accelerator/axel/blob/master/doc/axel.txt), [예제 설정에는 `default_filename`과 `no_clobber`가 포함되어 있습니다](https://github.com/axel-download-accelerator/axel/blob/master/doc/axelrc.example). 따라서 Axel을 사용하는 래퍼는 해당 파일에서 출력 파일명 설정을 물려받을 수도 있습니다. 유효한 `HOME`을 확인하세요. [sudo는 정책에 따라 `HOME`을 초기화하거나 유지할 수 있습니다](https://man7.org/linux/man-pages/man8/sudo.8.html). 사용자의 `.axelrc`는 권한이 높은 다운로드 프로그램이 실제로 이를 읽는 경우에만 관련이 있습니다. 수동 열거 중에는 다운로드를 시작하지 말고 규칙, 래퍼, 설정 파일 경로와 권한, 최종 출력 파일명, 대상 파일 상태를 확인하세요.

sudo 실행이 허용된 ACL 래퍼에서는 `setfacl`을 호출하기 전에 호출자가 선택한 파일을 어떻게 검증하는지 확인하세요. 문자열 기준 경로 접두사 확인과 `..` 거부만으로는 허용된 디렉터리 안의 심볼릭 링크가 외부 경로를 가리키는 것을 막을 수 없습니다. `test -f`도 링크를 따라갑니다. 래퍼가 충분한 권한으로 ACL 작업을 수행하는지, 호출자가 링크를 제어하는지, 결과 ACL이 대상 **및 상위 디렉터리**에서 필요한 접근 권한을 부여하는지 확인하세요. 일부 소비자는 쓰기 가능한 ACL이나 지나치게 느슨한 권한의 파일을 거부하므로, ACL 변경만으로 동작하는 권한 상승 경로가 성립하는 것은 아닙니다.

## 사용자가 마운트한 FUSE 파일시스템에 대한 권한 있는 쓰기 검토

`/etc/fuse.conf`에 활성화된 독립형 `user_allow_other` 행이 있으면, 루트가 아닌 사용자는 FUSE 마운트에 `allow_other` 또는 `allow_root`를 요청할 수 있습니다. 이러한 마운트 옵션을 사용하면 루트 프로세스가 마운트를 수행한 사용자가 구현한 파일시스템에 접근할 수 있습니다. sudo 실행이 허용된 헬퍼가 호출자가 제어하는 작업 디렉터리에 비밀이 포함된 로그나 기타 출력을 쓴다면, 해당 디렉터리가 사용자가 마운트한 FUSE 파일시스템일 수 있는지 검토하세요. 일반 파일시스템에서 결과 파일이 루트 소유 또는 `0600` 권한으로 보이더라도 FUSE 구현은 쓰기 작업을 관찰할 수 있습니다.

```bash
grep -n '^[[:space:]]*user_allow_other[[:space:]]*$' /etc/fuse.conf 2>/dev/null
sudo -l
```

이는 **가능성**일 뿐, 정보 노출의 증거는 아닙니다. 실제 sudo/run-as identity와 인수, helper의 출력 경로와 민감한 콘텐츠, `/dev/fuse`에 대한 접근 권한, `allow_other` 또는 `allow_root`를 사용한 마운트 성공 여부, 권한이 상승된 프로세스가 해당 마운트에 진입할 수 있는지 확인하세요. 일상적인 열거 중에는 권한이 상승된 helper를 실행하거나 파일시스템을 마운트하지 마세요. [libfuse 정책 설명](https://github.com/libfuse/libfuse/blob/master/util/fuse.conf) 및 [libfuse 접근 FAQ](https://github.com/libfuse/libfuse/wiki/FAQ#why-dont-other-users-have-access-to-the-mounted-filesystem)를 참조하세요.

## 경로 경쟁 조건 찾기

위험한 패턴은 권한이 상승된 프로그램이 어떤 경로명을 확인한 뒤, 확인한 객체에 대한 안전한 참조를 유지하지 않은 채 나중에 같은 경로명을 여는 것입니다. 상위 디렉터리를 제어하는 공격자는 두 작업 사이에 파일이나 symlink를 바꿀 수 있습니다. 임시 파일, 타이머로 실행되는 스크립트, 아카이브 추출, 백업 작업에서도 같은 문제가 발생합니다. 영향을 주장하기 전에 실제 읽기/쓰기 작업과 대상의 권한을 확인하세요.

아카이브 **생성**으로도 서로 다른 identity 간에 파일이 노출될 수 있습니다. Info-ZIP `zip -r`은 일반적으로 소스 트리 안에 있는 symlink를 따라가 대상의 콘텐츠를 저장합니다. 반면 `-y`/`--symlinks`는 링크 자체를 저장합니다. 낮은 권한의 사용자가 백업 대상 디렉터리에 링크를 추가할 수 있다면, 실제 archiver/options, 백업 작업의 읽기 identity, 생성된 아카이브를 해당 사용자가 읽을 수 있는지 확인하세요. 소스 디렉터리에 쓰기 권한이 있거나 symlink가 존재한다는 사실만으로는 정보 노출이 입증되지 않습니다. 백업을 실행하거나 열거 중 비밀 콘텐츠를 추출하지 말고 링크 및 아카이브 메타데이터를 검토하세요. [Info-ZIP 옵션 문서](https://sources.debian.org/src/zip/3.0-3/man/zip.1/#L1638)를 참조하세요.

GNU `tar`의 기본 동작은 다릅니다. 일반적으로 symlink를 링크로 저장하지만, 아카이브 생성 중 [`-h` / `--dereference`는 링크를 따라갑니다](https://www.gnu.org/software/tar/manual/html_node/dereference.html). 권한이 상승된 예약 백업의 경우, 정확한 `tar` 실행 명령, `tar`가 입력을 읽기 전에 낮은 권한의 사용자가 입력 경로명을 바꿀 수 있는지, 결과 아카이브에 해당 사용자가 접근할 수 있는지 확인하세요. 쓰기 가능한 스테이징 디렉터리에 있는 임시 checksum 파일이나 기타 sidecar가 이후 `tar -h` 명령에 명시적으로 지정되면 입력 파일이 될 수 있습니다. 경쟁 조건이 발생할 수 있는 시간 구간, 작업 identity, symlink 정책, 해당 identity로 대상 파일을 읽을 수 있는지, 아카이브 ACL을 모두 검증해야 합니다. 수동 점검 중에는 파일을 바꾸거나 작업을 실행하거나 민감한 아카이브를 풀지 마세요.

권한이 상승된 작업이 낮은 권한의 사용자가 교체할 수 있는 아카이브를 읽을 때는 아카이브 **추출**에서 또 다른 경계 문제가 발생합니다. [GNU tar는 superuser로 실행될 때 보통 아카이브에 저장된 소유권을 복원합니다](https://www.gnu.org/software/tar/manual/html_node/Option-Summary.html). 또한 [권한 복원 옵션](https://www.gnu.org/software/tar/manual/html_node/Setting-Access-Permissions.html)은 추출된 mode bit에 영향을 줍니다. 실제 extractor와 flags, 아카이브 교체 가능 시간 구간, 숫자 형식의 소유자 및 mode 메타데이터, 추출 디렉터리 권한, 정리 후 결과에 접근할 수 있는지 검토하세요. root 소유의 SUID 멤버는 추출 후 해당 mode가 유지되고 대상 mount 및 프로세스 정책이 identity 변경을 허용하는 경우에만 우려 대상입니다. 신뢰할 수 없는 아카이브나 쓰기 가능한 스테이징 경로만으로는 문제가 입증되지 않습니다. 수동 열거 중에는 아카이브를 교체하거나 추출하지 말고 작업 및 메타데이터를 확인하세요.

추출된 symlink는 이후 권한이 상승된 비교 작업을 통해 보호된 파일을 노출할 수도 있습니다. [GNU `diff`는 디렉터리를 비교할 때 일반적으로 symlink를 따라갑니다](https://www.gnu.org/software/diffutils/manual/html_node/Special-Files.html). 따라서 신뢰할 수 없는 추출 트리를 대상으로 root 권한으로 실행하는 `diff -r`은 링크 대상을 읽고, 차이가 있는 콘텐츠를 출력에 포함할 수 있습니다. 아카이브를 교체할 수 있는지, 링크가 비교 작업에서 실제로 탐색하는 경로에 연결되는지, 작업 identity로 대상을 읽을 수 있는지, 비교 출력 또는 오류 로그를 낮은 권한의 사용자가 읽을 수 있는지 확인하세요. 링크나 아카이브만으로는 정보 노출이 입증되지 않습니다. 열거 중 비교 작업을 실행하거나 보호된 콘텐츠를 읽지 말고 작업, 경로 메타데이터, 로그 권한을 검토하세요.

호스트 측에서 반복적으로 전송하는 작업이 신뢰할 수 없는 아카이브 멤버를 이후 출력 경로로 만들 수도 있습니다. 권한이 더 높은 작업이 신뢰도가 낮은 컨테이너에서 아카이브를 복사하고, 다음 전송의 대상 basename과 이름이 같은 symlink를 추출한 뒤, 나중에 같은 경로명에 기록한다면 이후 쓰기가 symlink 대상에 적용될 수 있습니다. 아카이브 멤버 이름과 대상, 추출 flags 및 디렉터리, extractor가 해당 링크를 실제로 남기는지, 기존 대상 링크를 전송 구현이 어떻게 처리하는지, 호스트 작업의 유효 쓰기 identity를 확인하세요. [GNU tar 문서는 추출 시 기존 파일과 symlink를 처리하는 방식을 설명합니다](https://www.gnu.org/software/tar/manual/html_section/extract-options.html). [최신 OpenSSH 버전에서 scp는 기본적으로 SFTP를 사용합니다](https://man.openbsd.org/scp.1). 따라서 모든 `scp` 버전이 링크를 따라 써 준다고 가정하지 말고 설치된 전송 동작을 확인하세요. 컨테이너에서 보이는 `scp` 프로세스나 쓰기 가능한 아카이브만으로는 호스트의 추출 및 이후 쓰기가 입증되지 않습니다. 열거 중에는 작업과 경로 메타데이터만 확인하고, 조작된 아카이브를 전송하거나 추출하지 마세요.

Ansible의 [`synchronize` module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/posix/synchronize_module.html)은 rsync를 래핑합니다. `copy_links: true`는 symlink 대신 symlink가 가리키는 대상을 복사합니다. 예약 백업의 경우 낮은 권한의 사용자가 정확한 소스 트리 안에 링크를 만들 수 있는지, 동기화 identity가 대상 파일을 읽을 수 있는지, 생성된 복사본이나 아카이브를 해당 사용자가 읽을 수 있는지 확인하세요. playbook, 링크 위치, run-as identity, 출력 권한이 모두 맞아야 합니다. 쓰기 가능한 업로드 디렉터리나 `copy_links` 설정만으로는 검토가 필요한 단서일 뿐입니다. 링크를 만들거나 작업을 실행하지 말고 메타데이터와 playbook을 확인하세요.

## 열린 파일 디스크립터 검사하기

```bash
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

프로세스는 파일이 삭제되거나 이름이 변경된 후에도 해당 파일에 계속 접근할 수 있습니다. 권한이 높은 프로세스는 Unix 소켓을 통해 디스크립터를 전달할 수도 있고, close-on-exec가 설정되지 않은 경우 `execve()` 이후에도 실수로 디스크립터를 열린 상태로 둘 수 있습니다. `/proc/<PID>/fd`의 대상을 확인해 민감한 파일, 삭제된 파일, 컨테이너 내부에서 보이는 호스트 경로, 예상치 못한 소켓이 있는지 살펴보세요. 다른 프로세스의 디스크립터를 역참조할 때는 커널 접근 검사가 적용됩니다. 심볼릭 링크가 보인다고 해서 그 대상의 내용을 읽을 수 있는 것은 아닙니다.

사용자 지정 SUID helper는 보호된 경로를 열고 유효 UID를 낮춘 뒤에도 디스크립터를 열린 상태로 둘 수 있습니다. 이후 스스로를 dumpable 상태로 설정하면 `/proc/<PID>/fd`의 소유권과 접근 권한이 달라질 수 있습니다. 정확한 자격 증명 전환, [`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html), procfs/ptrace 정책, 대상 파일 모드를 검토하세요. 디스크립터 경로를 다시 열면 접근할 수 없는 **상위 디렉터리**를 우회할 수 있지만, 호출자가 읽을 수 없는 파일을 여는 데는 실패할 수 있습니다. 디스크립터 대상이 보이거나 SUID 비트가 설정되어 있다는 사실만으로 정보 노출이 입증되는 것은 아닙니다.

크래시 산출물은 별도로 살펴볼 단서입니다. 코어 덤프에는 더 높은 권한으로 읽은 데이터를 포함해 프로세스 메모리가 들어 있을 수 있습니다. Ubuntu에서는 [Apport가 일반적으로 보고서를 `/var/crash`에 저장합니다](https://documentation.ubuntu.com/project/contributors/debugging/apport/). 다른 시스템에서는 다른 `core_pattern` 처리기나 systemd 저장소를 사용할 수 있습니다. 일반적인 열거 과정에서는 보고서의 경로, 소유자, 모드, 읽기 가능 여부만 확인하세요. 해당 프로세스가 dumpable 상태였고, 크래시 처리기가 민감한 바이트를 보존했으며, 현재 사용자가 해당 보고서에 접근할 수 있는 경우에만 읽을 수 있는 보고서가 의미가 있습니다. 수동 열거 과정에서 helper를 강제로 크래시시키거나 덤프를 압축 해제하지 마세요. SUID 및 덤프 생성 조건은 [`core(5)`](https://man7.org/linux/man-pages/man5/core.5.html)를 참조하세요.

서비스가 상속된 디스크립터를 사용하는 경우 셸 리디렉션이나 `/proc/self/fd/<N>`을 시도하기 전에 실행 체인과 디스크립터 번호를 확인하세요. 파일이 삭제되었지만 여전히 열린 상태라면 [삭제된 파일 복구](filesystem-inodes-and-recovery.md#deleted-file-recovery-through-open-fds)를 통해 증거를 보존하거나 내용을 복구할 수 있습니다. 프로세스 수준의 분류를 계속하려면 [프로세스 열거 및 서비스 경로](../processes-crontab-systemd-dbus/process-enumeration-and-service-paths.md)를 참조하세요.
{{#include ../../banners/hacktricks-training.md}}
