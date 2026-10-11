# 심볼릭 링크, 하드링크, 파일 디스크립터

{{#include ../../banners/hacktricks-training.md}}

경로는 확인되는 시점의 객체를 가리키며, 열린 파일 디스크립터는 경로명이 변경된 뒤에도 객체에 대한 참조를 유지합니다. 이 차이를 이해하면 심볼릭 링크 race, 숨겨진 하드링크, 삭제된 파일 복구, 상속된 디스크립터 leak을 설명할 수 있습니다. inode 및 mount에 대한 배경 정보는 [파일시스템, inode 및 복구](filesystem-inodes-and-recovery.md)를 참고하세요.

## 링크 및 경로 소유권 확인

```bash
namei -l /path/to/privileged/input
stat -c '%D %i %h %U:%G %a %n' /path/to/file
readlink -f /path/to/link
find /path/to/tree -type l -ls 2>/dev/null
find /path/to/tree -type f -links +1 -ls 2>/dev/null
```

심볼릭 링크는 경로명 해석을 다른 곳으로 돌리고, 하드 링크는 같은 파일시스템에서 동일한 inode를 가리키는 또 다른 이름입니다. 권한이 높은 작업이 사용자가 쓰기 가능한 디렉터리 안의 예측 가능한 경로를 읽거나 쓰는 경우, 사용자가 해당 경로를 민감한 대상으로 돌릴 수 있습니다. 최종 파일뿐 아니라 모든 상위 디렉터리의 소유권과 권한을 확인하세요. `fs.protected_symlinks`와 `fs.protected_hardlinks`는 일반적인 사용자 간 공격을 줄여 주지만, 쓰기 가능한 경로를 무조건 안전하게 만들지는 않습니다.

셸 glob으로 권한을 변경하는 권한 있는 작업에서는 **명령줄 피연산자**로 확장된 링크와 이후 재귀 탐색 중 발견된 링크를 구분하세요. [GNU `chmod`는 명령줄에 지정된 심볼릭 링크의 대상에 적용됩니다](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html). 반면 재귀 중에 만난 심볼릭 링크는 일반적으로 무시합니다. `-R`만으로 두 경우가 같아지지는 않습니다. 실제로 예약된 작업의 실행 사용자와 명령, 신뢰할 수 없는 사용자가 glob에 일치하는 항목을 만들 수 있는지, 설치된 `chmod`의 동작과 옵션, 제안된 대상에 적용될 권한을 확인하세요. 디렉터리가 쓰기 가능하거나 심볼릭 링크가 있다는 사실만으로 권한이 높은 작업이 권한을 변경한다고 단정할 수는 없습니다. 수동 열거 중에는 링크를 만들거나 작업을 실행하지 말고 스크립트와 경로 메타데이터를 확인하세요.

권한이 높은 예약 작업은 파일명에 무작위처럼 보이는 해시가 포함되어 있더라도 출력 경로를 예측 가능하게 만들 수 있습니다. [C `rand()`는 같은 `srand()` 시드에 대해 같은 수열을 반복합니다](https://man7.org/linux/man-pages/man3/rand.3.html). 여기에는 알려진 실행 시각에서 파생된 시드도 포함됩니다. 작업이 이름을 만들 때 호출자가 쓸 수 있는 데이터베이스 행도 읽는다면, 정확한 행-이름 변환 알고리즘, 시드와 libc 동작, 실행 일정, 호출자의 행 쓰기 및 디렉터리 생성 권한, 권한이 높은 프로세스가 파일을 열기 전에 기존 심볼릭 링크를 놓을 수 있는지를 확인하세요. [`fopen(..., "w")`는 해석된 파일을 만들거나 잘라냅니다](https://man7.org/linux/man-pages/man3/fopen.3.html). 링크 안전성을 보장하는 open 플래그나 원자적 교체 방식, 유효한 쓰기 권한을 가진 사용자, 대상 권한, sticky 디렉터리의 심볼릭 링크 정책을 실제 구현에서 확인하세요. 예측 가능한 이름이나 쓰기 가능한 행만으로는 검토할 단서일 뿐입니다. 수동 열거 중에는 행을 추가하거나 작업을 실행하지 말고 코드, 일정, 메타데이터를 확인하세요.

다른 사용자 권한으로 실행되는 파일 변환 서비스에서는 호출자가 출력 경로나 확장자를 선택할 수 있는지, 변환기가 기존 출력 심볼릭 링크를 따라가는지 확인하세요. 일부 변환기는 경로명의 확장자로 출력 형식을 선택합니다. 허용된 확장자를 가진 링크도 확장자가 없는 민감한 대상을 가리킬 수 있습니다. 사용자 간 쓰기가 성공하려면 서비스에 접근할 수 있고, 호출자가 경로와 링크를 제어하며, 변환기가 링크를 출력용으로 열고, 서비스 실행 사용자가 쓰기 권한을 가져야 합니다. Linux의 `fs.protected_symlinks=1`은 **sticky 비트가 설정된 모든 사용자 쓰기 가능 디렉터리**에서 다른 사용자의 링크를 따라가는 것을 제한합니다. 일반적인 사용자 소유 디렉터리의 링크에는 같은 보호를 제공하지 않습니다. 결론을 내리기 전에 해석된 경로와 상위 디렉터리의 소유권을 확인하세요. [calibre의 출력 파일 동작](https://manual.calibre-ebook.com/generated/en/ebook-convert.html) 및 [Linux 심볼릭 링크 정책](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks)을 참조하세요.

sudo 실행이 허용된 다운로드 래퍼가 호출자 선택 데이터를 가져오는 동안 호출자가 제어하는 작업 디렉터리를 유지한다면, 같은 출력 경로 검토가 필요합니다. 실제 다운로드 프로그램을 확인하고, 선택된 기본 파일명, 충돌 처리, 기존 심볼릭 링크가 권한이 높은 쓰기를 다른 곳으로 돌릴 수 있는지 살펴보세요. URL 선택이나 심볼릭 링크만으로는 충분하지 않습니다. [Axel은 사용자별 `~/.axelrc`를 문서화하고 있으며](https://github.com/axel-download-accelerator/axel/blob/master/doc/axel.txt), [예제 설정에는 `default_filename`과 `no_clobber`가 포함됩니다](https://github.com/axel-download-accelerator/axel/blob/master/doc/axelrc.example). 따라서 Axel을 사용하는 래퍼는 이 파일의 출력 이름 설정도 상속할 수 있습니다. 유효한 `HOME`을 확인하세요. [sudo는 정책에 따라 이를 초기화하거나 유지할 수 있습니다](https://man7.org/linux/man-pages/man8/sudo.8.html). 사용자의 `.axelrc`는 권한이 높은 다운로드 프로그램이 실제로 읽는 경우에만 관련이 있습니다. 수동 열거 중에는 다운로드를 시작하지 말고 규칙, 래퍼, 설정 파일 경로와 권한, 최종 출력 파일명, 대상 파일 상태를 확인하세요.

sudo 실행이 허용된 ACL 래퍼에서는 `setfacl`을 호출하기 전에 호출자가 선택한 파일을 어떻게 검증하는지 확인하세요. 어휘적 접두사 검사와 `..` 거부만으로는 허용된 디렉터리 안의 심볼릭 링크가 외부를 가리키는 것을 막을 수 없습니다. `test -f`도 링크를 따라갑니다. 래퍼가 충분한 권한으로 ACL 작업을 수행하는지, 호출자가 링크를 제어하는지, 결과 ACL이 대상 **및 상위 디렉터리**에 필요한 접근 권한을 부여하는지 확인하세요. 일부 프로그램은 쓰기 가능한 ACL이나 느슨한 권한의 파일을 거부하므로 ACL만 변경했다고 해서 실제 권한 상승 경로가 성립하는 것은 아닙니다.

## 사용자 마운트 FUSE 파일시스템에 대한 권한 있는 쓰기 검토

`/etc/fuse.conf`에 활성화된 독립형 `user_allow_other` 행이 있으면 일반 사용자는 FUSE 마운트에 `allow_other` 또는 `allow_root`를 요청할 수 있습니다. 이러한 마운트 옵션을 사용하면 root 프로세스가 마운트를 만든 사용자가 구현한 파일시스템에 접근할 수 있습니다. sudo 실행이 허용된 헬퍼가 호출자가 제어하는 작업 디렉터리를 기준으로 비밀 정보가 포함된 로그나 다른 출력을 쓴다면, 해당 디렉터리가 사용자 마운트 FUSE 파일시스템일 수 있는지 검토하세요. 일반 파일시스템에서 결과 파일이 root 소유 또는 모드 `0600`으로 표시되더라도 FUSE 구현은 쓰기를 관찰할 수 있습니다.

```bash
grep -n '^[[:space:]]*user_allow_other[[:space:]]*$' /etc/fuse.conf 2>/dev/null
sudo -l
```

이는 정보 노출의 **가능성**일 뿐, 노출의 증거는 아닙니다. 실제 sudo/run-as identity와 인자, helper의 출력 경로와 민감한 내용, `/dev/fuse` 접근 권한, `allow_other` 또는 `allow_root`를 사용한 mount 성공 여부, 그리고 privileged process가 mount에 진입할 수 있는지 확인하세요. 일반적인 enumeration 중에는 privileged helper를 실행하거나 filesystem을 mount하지 마세요. [libfuse policy 설명](https://github.com/libfuse/libfuse/blob/master/util/fuse.conf) 및 [libfuse access FAQ](https://github.com/libfuse/libfuse/wiki/FAQ#why-dont-other-users-have-access-to-the-mounted-filesystem)를 참고하세요.

## path race 확인

위험한 패턴은 privileged program이 pathname을 확인한 뒤, 확인한 객체에 대한 안전한 참조를 유지하지 않은 채 나중에 같은 pathname을 여는 것입니다. parent directory를 제어하는 공격자는 두 작업 사이에 파일이나 symlink를 바꿀 수 있습니다. 같은 문제가 temporary file, timer-driven script, archive extraction, backup workflow에서도 나타납니다. 영향이 있다고 주장하기 전에 실제 read/write 작업과 대상의 permissions를 확인하세요.

Archive **생성**도 identity 간 파일을 노출할 수 있습니다. Info-ZIP `zip -r`은 일반적으로 source tree 안에 있는 symlink를 따라가서 대상의 내용을 저장합니다. 반면 `-y`/`--symlinks`는 link 자체를 저장합니다. 낮은 권한의 사용자가 백업 대상 directory에 link를 추가할 수 있다면, 정확한 archiver/options, backup job의 read identity, 그리고 생성된 archive를 해당 사용자가 읽을 수 있는지 확인하세요. source directory에 쓰기 권한이 있거나 symlink가 있다는 사실만으로는 노출이 입증되지 않습니다. 백업을 실행하거나 enumeration 중에 비밀 내용을 추출하지 말고 link 및 archive metadata를 검토하세요. [Info-ZIP option 문서](https://sources.debian.org/src/zip/3.0-3/man/zip.1/#L1638)를 참고하세요.

GNU `tar`의 기본 동작은 다릅니다. 일반적으로 symlink를 link로 저장하며, [`-h` / `--dereference`는 archive 생성 중 symlink를 따라갑니다](https://www.gnu.org/software/tar/manual/html_node/dereference.html). privileged scheduled backup의 경우, 정확한 `tar` 호출 방식, 낮은 권한의 사용자가 `tar`가 읽기 전에 입력 pathname을 바꿀 수 있는지, 생성된 archive에 해당 사용자가 접근할 수 있는지 확인하세요. 쓰기 가능한 staging directory의 임시 checksum 또는 기타 sidecar가 나중에 실행되는 `tar -h` 명령에 명시적으로 지정되면 입력 파일이 될 수 있습니다. race window, job identity, symlink policy, 해당 identity로 대상 파일을 읽을 수 있는지, archive ACL을 모두 확인해야 합니다. passive check 중에는 파일을 교체하거나 job을 실행하거나 민감한 archive를 풀지 마세요.

privileged job이 낮은 권한의 사용자가 교체할 수 있는 archive를 읽을 때, archive **추출**은 또 다른 경계를 넘을 수 있습니다. [GNU tar는 superuser로 실행할 때 일반적으로 archive의 ownership을 복원합니다](https://www.gnu.org/software/tar/manual/html_node/Option-Summary.html). 또한 [permission 복원 options](https://www.gnu.org/software/tar/manual/html_node/Setting-Access-Permissions.html)는 추출되는 mode bits에 영향을 줍니다. 정확한 extractor와 flags, archive 교체 가능 기간, numeric owner 및 mode metadata, extraction directory permissions, 정리 후에도 결과에 접근할 수 있는지 검토하세요. root 소유 SUID member는 추출 후에도 mode가 유지되고 대상 mount와 process policy가 identity 변경을 허용하는 경우에만 우려 대상입니다. 신뢰할 수 없는 archive나 쓰기 가능한 staging path만으로는 이를 입증할 수 없습니다. passive enumeration 중에는 archive를 교체하거나 추출하지 말고 job과 metadata를 확인하세요.

추출된 symlink는 나중에 privileged comparison을 통해 보호된 파일을 노출할 수도 있습니다. [GNU `diff`는 directory를 비교할 때 일반적으로 symlink를 따라갑니다](https://www.gnu.org/software/diffutils/manual/html_node/Special-Files.html). 따라서 신뢰할 수 없는 추출 tree를 대상으로 root가 실행하는 `diff -r`은 symlink 대상 파일을 읽고, 서로 다른 내용을 출력에 포함할 수 있습니다. archive를 교체할 수 있는지, link가 비교 과정에서 실제로 방문하는 경로에 생성되는지, job이 대상 파일을 읽을 수 있는지, comparison 출력 또는 error log를 낮은 권한의 사용자가 읽을 수 있는지 확인하세요. link나 archive만으로는 노출이 입증되지 않습니다. enumeration 중에는 comparison을 실행하거나 보호된 내용을 읽지 말고 job, path metadata, log permissions를 검토하세요.

반복되는 host-side transfer로 인해 신뢰할 수 없는 archive member가 이후 출력 경로가 될 수 있습니다. 높은 권한의 job이 낮은 신뢰 수준의 container에서 archive를 복사하고, 다음 transfer의 destination basename과 이름이 같은 symlink를 추출한 뒤, 나중에 같은 pathname에 쓰는 경우 이후 쓰기가 symlink 대상에 도달할 수 있습니다. archive member의 이름과 대상, extraction flags와 directory, extractor가 실제로 해당 link를 남기는지, 기존 destination symlink를 transfer 구현이 어떻게 처리하는지, host job의 유효한 write identity를 확인하세요. [GNU tar는 추출 시 기존 파일과 symlink를 처리하는 방법을 설명합니다](https://www.gnu.org/software/tar/manual/html_section/extract-options.html). [OpenSSH scp는 최신 버전에서 기본적으로 SFTP를 사용합니다](https://man.openbsd.org/scp.1). 따라서 모든 `scp` 버전이 symlink를 따라 파일에 쓴다고 가정하지 말고, 설치된 transfer 동작을 확인하세요. container에서 보이는 `scp` process나 쓰기 가능한 archive만으로는 host 측의 추출과 이후 쓰기를 입증할 수 없습니다. enumeration 중에는 crafted archive를 전송하거나 추출하지 말고 job과 path metadata를 확인하세요.

Ansible의 [`synchronize` module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/posix/synchronize_module.html)은 rsync를 래핑합니다. `copy_links: true`는 symlink 자체 대신 symlink가 가리키는 파일을 복사합니다. scheduled backup의 경우, 낮은 권한의 사용자가 정확한 source tree 안에 link를 만들 수 있는지, synchronization identity가 대상 파일을 읽을 수 있는지, 생성된 복사본이나 archive를 해당 사용자가 읽을 수 있는지 확인하세요. playbook, link 위치, run-as identity, 출력 permissions가 모두 맞아야 합니다. 업로드 directory에 쓰기 권한이 있거나 `copy_links`가 설정되어 있다는 사실만으로는 검토할 단서일 뿐입니다. link를 만들거나 job을 실행하지 말고 metadata와 playbook을 확인하세요.

## 열린 descriptor 확인

```bash
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

프로세스는 파일이 삭제되거나 이름이 변경된 후에도 해당 파일에 대한 접근 권한을 유지할 수 있습니다. 권한이 높은 프로세스는 Unix socket을 통해 descriptor를 전달할 수도 있고, close-on-exec가 설정되지 않은 경우 `execve()` 후에도 의도치 않게 descriptor를 열린 상태로 남길 수 있습니다. `/proc/<PID>/fd`의 대상을 확인해 민감한 파일, 삭제된 파일, 컨테이너 내부에서 보이는 호스트 경로, 예상치 못한 socket이 있는지 살펴보세요. 다른 프로세스의 descriptor를 역참조할 때는 커널의 접근 검사가 적용됩니다. symlink가 보인다고 해서 대상의 내용을 읽을 수 있는 것은 아닙니다.

사용자 지정 SUID helper는 보호된 경로를 열고 effective UID를 낮춘 뒤 descriptor를 열린 상태로 남길 수 있습니다. 이후 dumpable 상태로 설정되면 `/proc/<PID>/fd`의 소유권과 접근 권한이 달라질 수 있습니다. 정확한 credential 전환, [`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html), procfs/ptrace 정책, 대상 파일의 mode를 확인하세요. descriptor 경로를 다시 열면 접근할 수 없는 **상위 디렉터리**를 우회할 수 있지만, 호출자가 읽을 수 없는 파일은 여전히 열 수 없습니다. 대상 descriptor가 보이거나 SUID bit가 설정되어 있다는 사실만으로 정보가 노출된다고 단정할 수는 없습니다.

크래시 artifact는 별도로 살펴볼 단서입니다. core dump에는 더 높은 권한으로 실행되던 동안 읽은 데이터를 포함해 프로세스 메모리가 들어 있을 수 있습니다. Ubuntu에서는 [Apport가 일반적으로 보고서를 `/var/crash`에 저장합니다](https://documentation.ubuntu.com/project/contributors/debugging/apport/). 다른 시스템은 다른 `core_pattern` handler나 systemd 저장소를 사용할 수 있습니다. 일반적인 열거 단계에서는 보고서 경로, 소유자, mode, 읽기 가능 여부만 확인하세요. 관련 프로세스가 dumpable 상태였고, 크래시 handler가 민감한 데이터를 보존했으며, 현재 사용자가 해당 보고서에 접근할 수 있는 경우에만 읽을 수 있는 보고서가 의미가 있습니다. 수동 열거의 일환으로 helper를 강제 종료하거나 dump를 풀지 마세요. SUID 및 dump 생성 조건은 [`core(5)`](https://man7.org/linux/man-pages/man5/core.5.html)를 참고하세요.

서비스가 상속된 descriptor를 사용한다면, shell redirection이나 `/proc/self/fd/<N>`을 시도하기 전에 실행 체인과 descriptor 번호를 확인하세요. 파일이 삭제되었지만 계속 열린 상태라면 [삭제된 파일 복구](filesystem-inodes-and-recovery.md#deleted-file-recovery-through-open-fds)를 통해 증거를 보존하거나 내용을 복구할 수 있습니다. 프로세스 수준의 triage는 [프로세스 열거 및 서비스 경로](../processes-crontab-systemd-dbus/process-enumeration-and-service-paths.md)를 이어서 확인하세요.
{{#include ../../banners/hacktricks-training.md}}
