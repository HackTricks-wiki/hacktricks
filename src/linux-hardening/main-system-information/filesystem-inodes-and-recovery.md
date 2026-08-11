# 파일 시스템, Inode 및 복구

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse는 눈에 보이는 경로와 그 뒤에 있는 객체의 관계를 혼동시키는 방식으로 이루어지는 경우가 많습니다.

Disk image는 다른 파일 시스템을 숨길 수 있습니다.<sup>[[1]](#references)</sup> Writable mount는 privileged job에 의해 사용될 수 있습니다.

Hardlink는 다른 이름을 통해 동일한 inode를 노출할 수 있습니다.<sup>[[3]](#references)</sup> 삭제된 파일도 열린 file descriptor를 통해 여전히 읽을 수 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

이 페이지는 특정 lab이나 target이 아니라 해당 technique에 초점을 맞춥니다.

## Disk Image 및 Loop Mount

일반 파일에는 완전한 파일 시스템이 포함될 수 있으므로, disk image를 mount하면 두 번째 파일 시스템 트리가 노출될 수 있습니다.<sup>[[1]](#references)</sup>

Backup image, 복사된 block device, VM artifact 또는 이름이 변경된 blob에는 외부에서 유용해 보이지 않더라도 credential, script, SSH key, configuration file 또는 flag가 포함되어 있을 수 있습니다.

`file`로 후보를 분류하고, `blkid`로 인식 가능한 파일 시스템 metadata를 확인하며, `strings -a`로 파일 전체에서 출력 가능한 문자열을 검색하여 가능성 있는 image를 식별합니다.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
마운트가 허용되는 경우 `ro`를 사용한 loop mount로 이미지를 읽기 전용으로 연결합니다. 아래의 `find` 명령은 검사 깊이와 파일 유형을 제한합니다.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
마운트를 사용할 수 없고 이미지가 ext2/ext3/ext4인 경우, `debugfs`를 사용하여 메타데이터를 직접 검사합니다.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
이 technique은 일반적인 파일처럼 보이는 파일을 두 번째 filesystem tree로 바꾸기 때문에 유용합니다.<sup>[[1]](#references)</sup> 이를 privilege escalation 그 자체가 아니라 숨겨진 데이터를 복구하는 방법으로 간주하세요.

## Writable Mount Abuse

더 높은 privilege의 context가 나중에 해당 mount 내부의 무언가를 신뢰할 때 writable mount가 위험해집니다. 중요한 질문은 단순히 "여기에 쓸 수 있는가?"가 아니라 "나중에 누가 여기에서 읽거나, 실행하거나, import하거나, load하는가?"입니다.

`findmnt`를 사용하여 mounted filesystem과 해당 옵션을 검사하세요.<sup>[[9]](#references)</sup>

문서화된 `find`의 permission, type 및 filesystem-boundary predicate를 사용하여 writable mount와 의심스러운 consumer를 찾은 다음, recursive `grep`을 사용하여 가능성이 높은 consumer configuration을 검색하세요.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
일반적인 악용 패턴:

- cron job 또는 systemd service가 mount에서 writable script를 실행합니다.<sup>[[13]](#references)[[14]](#references)</sup>
- privileged service가 mount에서 plugin, config, template 또는 helper binary를 로드합니다.
- mount에 SUID 파일이 포함되어 있으며 수정, 교체 또는 path manipulation이 가능합니다.
- container 또는 chroot가 제한된 환경에서 쓰기 가능한 host-backed path를 노출합니다. Mount namespace는 서로 다른 mount hierarchy를 제공하는 반면, `chroot()`는 pathname resolution만 변경하며 완전한 sandbox가 아닙니다.<sup>[[15]](#references)[[16]](#references)</sup>

동일한 `find` predicates를 사용하는 일반적인 validation pattern입니다.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
승인된 lab에서 impact를 입증할 때는 payload를 관찰 가능하고 최소한으로 유지하세요. 예를 들어 `id` 출력을 임시 파일에 기록할 수 있습니다.<sup>[[23]](#references)</sup> 핵심 technique은 신뢰할 수 있는 writable location을 통한 지연 실행입니다.

## Inodes and Path Confusion

inode는 파일시스템 객체이고, path는 해당 객체를 가리키는 이름일 뿐입니다. device 및 inode metadata를 사용하면 파일시스템 간 객체를 구분할 수 있으며, link count를 통해 여러 hard link를 확인할 수 있습니다.<sup>[[3]](#references)</sup> 프로세스가 파일을 계속 열어 둔 상태에서는 pathname이 삭제되어도 데이터가 항상 사라지는 것은 아닙니다.<sup>[[5]](#references)</sup>

아래의 `find` predicates는 inode identity, link count, device 경계 및 timestamp를 비교합니다.<sup>[[4]](#references)</sup>

`ls -i` 및 `stat` metadata format을 사용하여 inode와 device를 기준으로 파일을 비교합니다.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
`find -samefile`을 사용하여 동일한 inode에 대한 모든 visible pathname을 찾습니다.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
메타데이터만 가지고 있을 때는 `find -inum`을 사용해 inode 번호로 직접 검색합니다.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
이 technique은 파일이 예상치 못한 이름으로 나타나거나, 애플리케이션이 한 경로를 검증하지만 다른 경로를 사용하거나, 권한 있는 wrapper가 다른 위치에서도 접근 가능한 inode와 상호 작용할 때 유용합니다.

## Hardlink Abuse

Hardlink는 동일한 inode에 대해 여러 이름을 생성합니다. Symlink처럼 대상 경로를 가리키는 것이 아니라, 동일한 파일 객체에 대한 동등한 이름입니다.<sup>[[3]](#references)</sup>

`find`의 권한 및 link-count predicate를 사용하여 여러 hardlink가 있는 SUID 파일을 찾습니다.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
`stat` 및 `find -samefile`을 사용하여 의심스러운 파일 하나를 검사합니다.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
중요한 이유:

- 민감한 파일에 덜 obvious한 경로를 통해 접근할 수 있습니다.
- SUID wrapper가 권한이 필요한 것처럼 보이지 않는 이름 뒤에 숨겨져 있을 수 있습니다.
- 하나의 pathname을 삭제하는 cleanup으로도 다른 hardlink가 남아 있을 수 있습니다.

Linux의 `fs.protected_hardlinks` sysctl은 권한 경계를 넘어선 hardlink 생성을 제한할 수 있습니다.<sup>[[7]](#references)</sup> 기존 hardlink도 검토할 가치가 있습니다.

## Open FDs를 통한 삭제된 파일 복구

프로세스가 파일을 열어 둔 상태에서 마지막 pathname을 unlink하면 마지막 descriptor가 닫힐 때까지 파일이 유지됩니다. Linux는 이러한 descriptor를 `/proc/<pid>/fd/` 아래에 노출합니다.<sup>[[5]](#references)[[6]](#references)</sup>

`/proc` descriptor를 나열하고 open-file 출력을 필터링하여 삭제된 open file을 찾을 수 있습니다.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
이러한 링크를 통한 복구는 권한에 따라 달라집니다. `/proc/<pid>/fd` 역참조에는 ptrace access checks와 파일 권한이 적용되기 때문입니다.<sup>[[6]](#references)</sup>

허용되는 경우 `readlink`은 descriptor target을 표시하고 `cp`는 해당 내용을 복사합니다.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
삭제된 로그, 임시 secret, 삭제된 binary, rotate된 파일 또는 실행 후 제거된 script를 복구하기 위한 practical technique입니다.

## debugfs를 사용한 ext Recovery

ext2/ext3/ext4 파일 시스템에서 `debugfs`는 block device 또는 image에서 inode metadata를 검사하고 inode contents를 dump할 수 있으며, `-w` 없이 실행하면 파일 시스템을 read-only로 엽니다.<sup>[[2]](#references)</sup> 가능한 경우 항상 복사본 또는 read-only image에서 작업하세요.

directory listing, inode status 및 inode-to-path 확인을 위한 `debugfs` request를 사용해 entries를 나열하고 inode를 검사하세요.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
`debugfs dump` 명령어로 알려진 inode를 덤프한 다음, `file`을 사용하여 복구된 출력을 분류합니다.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
이는 복구를 보장하지 않습니다. 파일시스템 상태, 블록 재사용 여부, 메타데이터가 여전히 존재하는지에 따라 달라집니다. ext3/ext4의 경우 `debugfs` 매뉴얼에서는 해제된 inode 데이터 블록을 더 이상 사용할 수 없기 때문에 삭제된 inode 복구가 실패할 수 있다고 설명합니다.<sup>[[2]](#references)</sup> 이 기법은 일반적인 경로 순회에 의존하지 않고 inode 수준의 상태를 검사할 수 있게 해 주므로 여전히 유용합니다.

## Inode 고갈 및 순서

Inode 고갈은 여유 디스크 공간이 남아 있더라도 파일시스템에 파일 노드가 부족해질 때 발생합니다.<sup>[[8]](#references)[[17]](#references)</sup> 일반적으로 안정성 문제가 발생하지만, incident response 또는 lab triage 중 이상한 동작을 설명하는 데에도 도움이 될 수 있습니다.

블록 사용량 대신 inode 정보를 표시하려면 `df -i`를 사용합니다.<sup>[[8]](#references)</sup>

`df`와 디렉터리 부모를 세는 `find`를 사용하여 inode pressure를 확인합니다.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode 번호와 timestamp는 간단한 lab 환경에서 활동을 재구성하는 데에도 도움이 됩니다.

아래의 `find` format directives는 이러한 필드를 표시합니다.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
순서를 단서로 사용하되, 증거로 간주하지 마세요. 복사 작업, archive 추출, filesystem 유형, 복원 작업 및 concurrent writes는 모두 allocation 패턴을 변경할 수 있습니다.

## 방어 참고 사항

- 분석 중에는 알 수 없는 이미지를 read-only로 mount하세요.<sup>[[1]](#references)</sup>
- privileged scripts, service units, plugins 및 helper paths를 user-writable mounts 외부에 유지하세요.
- 운영상 적절한 경우 `nosuid`, `nodev` 및 `noexec`를 사용하세요. 이러한 옵션은 mount에서 set-ID/capability 실행, device 해석 또는 직접적인 binary 실행을 비활성화합니다.<sup>[[1]](#references)</sup> 이를 완전한 boundary로 간주하지 마세요.
- `/proc/<pid>/fd`에 대한 access를 제한하세요. 해당 links의 dereferencing은 ptrace access checks 및 file permissions에 의해 제어됩니다.<sup>[[6]](#references)</sup> 가능한 경우 더 광범위한 process metadata 및 cross-user inspection도 제한하세요.
- writable mount points, privileged files에 대한 예기치 않은 hardlinks 및 deleted-but-open sensitive files를 monitor하세요.

## References

- [1] [mount(8) — Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux manual page](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux manual page](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux manual page](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [/proc/sys/fs/에 대한 문서 — Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux manual page](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux manual page](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux manual page](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux manual page](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux manual page](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux manual page](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux manual page](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux manual page](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
