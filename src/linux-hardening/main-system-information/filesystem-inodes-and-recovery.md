# 파일시스템, Inode 및 복구

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse는 보이는 경로와 그 뒤에 있는 객체의 관계를 혼동시키는 것과 관련된 경우가 많습니다. Disk image에는 다른 filesystem이 숨겨져 있을 수 있고, writable mount는 privileged job에서 사용될 수 있으며, hardlink를 사용하면 다른 이름을 통해 동일한 inode를 노출할 수 있습니다. 또한 삭제된 파일도 열린 file descriptor를 통해 여전히 읽을 수 있습니다.

이 페이지에서는 특정 lab이나 target이 아닌 technique에 초점을 맞춥니다.

## Disk Image 및 Loop Mount

일반 파일에는 완전한 filesystem이 포함될 수 있습니다. 따라서 backup image, 복사된 block device, VM artifact 또는 이름이 변경된 blob에는 외부에서 유용해 보이지 않더라도 credential, script, SSH key, configuration file 또는 flag가 포함되어 있을 수 있습니다.

가능성이 높은 image를 식별합니다:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
마운트가 허용되는 경우, 알 수 없는 이미지는 먼저 읽기 전용으로 마운트하세요:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
mounting을 사용할 수 없다면 파일시스템 메타데이터를 직접 검사합니다:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
이 technique은 일반적으로 보이는 파일을 두 번째 filesystem tree로 바꾸기 때문에 유용합니다. 이를 privilege escalation 자체가 아니라 숨겨진 data를 복구하는 방법으로 간주하세요.

## Writable Mount Abuse

더 높은 privilege를 가진 context가 나중에 그 안의 무언가를 신뢰할 때 writable mount는 위험해집니다. 중요한 질문은 단순히 "여기에 쓸 수 있는가?"가 아니라 "나중에 누가 여기에서 읽거나, 실행하거나, import하거나, load하는가?"입니다.

writable mount와 의심스러운 consumer를 찾으세요:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
일반적인 악용 패턴:

- 권한 있는 cron 또는 systemd unit이 마운트에서 writable script를 실행합니다.
- 권한 있는 service가 마운트에서 plugins, config, templates 또는 helper binaries를 로드합니다.
- 마운트에 SUID files가 포함되어 있으며 수정, 교체 또는 path manipulation이 허용됩니다.
- container 또는 chroot가 제한된 환경에서 writable한 host-backed path를 노출합니다.

일반적인 검증 패턴:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
승인된 lab에서 impact를 입증할 때는 payload를 관찰 가능하고 최소한으로 유지하세요. 예를 들어 `id` 출력을 임시 파일에 기록할 수 있습니다. 핵심 technique은 신뢰할 수 있는 쓰기 가능한 위치를 통한 지연 실행입니다.

## Inodes 및 Path Confusion

inode는 filesystem object이고, path는 이를 가리키는 이름일 뿐입니다. 이는 서로 다른 두 path가 동일한 inode를 가리킬 수 있으며, 삭제된 pathname이 항상 데이터가 사라졌음을 의미하지는 않기 때문에 중요합니다.

inode와 device를 기준으로 파일을 비교하세요:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
동일한 inode에 대한 모든 표시 가능한 경로 찾기:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
메타데이터만 가지고 있을 때 inode 번호로 직접 검색하세요:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
이 technique은 파일이 예상치 못한 이름으로 나타나거나, 애플리케이션이 한 경로를 검증하지만 다른 경로를 사용하거나, 권한 있는 wrapper가 다른 위치에서도 접근 가능한 inode와 상호작용할 때 유용합니다.

## Hardlink Abuse

Hardlink는 동일한 inode에 여러 이름을 생성합니다. symlink처럼 대상 경로를 가리키는 것이 아니라, 동일한 파일 객체에 대한 동일한 이름입니다.

여러 hardlink가 있는 SUID 파일 찾기:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
의심스러운 파일 하나를 검사합니다:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
중요한 이유:

- 민감한 파일이 덜 명확한 경로를 통해 접근 가능할 수 있습니다.
- SUID wrapper가 권한이 있어 보이지 않는 이름 뒤에 숨겨져 있을 수 있습니다.
- 하나의 pathname을 삭제하는 cleanup 작업을 수행해도 다른 hardlink가 남아 있을 수 있습니다.

Modern kernel과 mount option은 이러한 유형의 abuse를 줄이기 위해 hardlink 생성을 제한할 수 있지만, 기존 hardlink는 여전히 검토할 가치가 있습니다.

## Open FD를 통한 Deleted File Recovery

process가 파일을 open 상태로 유지하면 pathname이 삭제된 후에도 파일 data에 계속 접근할 수 있습니다. Linux는 이러한 open descriptor를 `/proc/<pid>/fd/` 아래에 노출합니다.

삭제된 open file 찾기:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
권한이 허용되는 경우 데이터를 복구합니다:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
삭제된 로그, 임시 secret, 삭제된 바이너리, rotate된 파일 또는 실행 후 제거된 스크립트를 복구하기 위한 실용적인 technique입니다.

## debugfs를 사용한 ext 복구

ext filesystem에서는 `debugfs`를 사용해 inode 메타데이터를 검사하고, 경우에 따라 filesystem image에서 파일 콘텐츠를 덤프할 수 있습니다. 가능한 경우 항상 복사본 또는 read-only image에서 작업하세요.

항목을 나열하고 inode를 검사합니다:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
알려진 inode 덤프:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
이는 복구를 보장하지 않습니다. 파일 시스템 상태, 블록이 재사용되었는지 여부, 메타데이터가 여전히 존재하는지에 따라 달라집니다. 이 기법은 일반적인 경로 순회에 의존하지 않고 inode 수준의 상태를 검사할 수 있으므로 여전히 유용합니다.

## Inode 고갈 및 순서

Inode 고갈은 여유 디스크 공간이 남아 있더라도 파일 시스템에 파일 객체가 부족해질 때 발생합니다. 일반적으로 안정성 문제가 발생하지만, incident response 또는 lab triage 중 이상한 동작을 설명하는 데에도 도움이 될 수 있습니다.

Inode 압박 상태를 확인합니다:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode 번호와 타임스탬프는 간단한 실습 환경에서 활동을 재구성하는 데에도 도움이 될 수 있습니다:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
순서는 단서로만 취급하고, 증거로 간주하지 마세요. 복사 작업, archive 추출, filesystem type, 복원 및 동시 쓰기는 모두 allocation pattern을 변경할 수 있습니다.

## 방어 참고 사항

- 분석 중에는 알 수 없는 image를 read-only로 mount하세요.
- privileged script, service unit, plugin 및 helper path를 user-writable mount 외부에 유지하세요.
- 운영상 적절한 경우 `nosuid`, `nodev`, `noexec`를 사용하되, 이를 완전한 경계로 간주하지 마세요.
- 가능한 경우 `/proc/<pid>/fd`, process metadata 및 cross-user process inspection에 대한 접근을 제한하세요.
- writable mount point, privileged file에 대한 예기치 않은 hardlink 및 삭제되었지만 열려 있는 민감한 file을 monitor하세요.
