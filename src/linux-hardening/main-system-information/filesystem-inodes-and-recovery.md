# Файлова система, inode та відновлення

{{#include ../../banners/hacktricks-training.md}}

Зловживання файловою системою часто полягає в заплутуванні взаємозв'язку між видимим шляхом і об'єктом, що стоїть за ним. Образи дисків можуть приховувати іншу файлову систему, доступні для запису монтування можуть використовуватися привілейованими завданнями, hardlinks можуть відкривати доступ до того самого inode через інше ім'я, а видалені файли все ще можуть бути доступними для читання через відкритий дескриптор файлу.

Ця сторінка зосереджена на техніці, а не на конкретній лабораторній роботі чи цілі.

## Образи дисків і loop-монтування

Звичайний файл може містити повну файлову систему. Тому образи резервних копій, скопійовані блокові пристрої, артефакти VM або перейменовані blobs можуть містити облікові дані, скрипти, SSH-ключі, конфігураційні файли або flags, навіть якщо зовні вони не здаються корисними.

Визначте ймовірні образи:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Якщо монтування дозволено, спочатку монтуйте невідомі образи в режимі лише для читання:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Якщо монтування недоступне, безпосередньо перевірте метадані файлової системи:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
The technique is useful because it turns a normal-looking file into a second filesystem tree. Treat it as a way to recover hidden data, not as a privilege escalation by itself.

## Writable Mount Abuse

Writable mount becomes dangerous when a more privileged context later trusts something inside it. The important question is not only "чи можу я записувати сюди?", but "хто згодом читає, виконує, імпортує або завантажує звідси?".

Find writable mounts and suspicious consumers:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Типові шаблони зловживань:

- Привілейований cron або systemd unit запускає доступний для запису скрипт із mount.
- Привілейований сервіс завантажує plugins, config, templates або helper binaries із mount.
- Mount містить SUID-файли та дозволяє їх модифікацію, заміну або маніпуляції з path.
- Container або chroot відкриває доступ до path, прив'язаного до host, який доступний для запису з restricted environment.

Загальний шаблон перевірки:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Під час демонстрації впливу в авторизованій лабораторії тримайте payload видимим і мінімальним, наприклад записуючи вивід `id` у тимчасовий файл. Основна техніка полягає у відкладеному виконанні через довірене місце, доступне для запису.

## Inodes і плутанина шляхів

Inode є об'єктом файлової системи; шлях — лише ім'я, що вказує на нього. Це важливо, оскільки два різні шляхи можуть вказувати на один і той самий inode, а видалення pathname не завжди означає, що дані зникли.

Порівнюйте файли за inode і пристроєм:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Знайдіть усі видимі шляхи до того самого inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Шукайте безпосередньо за номером inode, коли у вас є лише метадані:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ця техніка корисна, коли файл має неочікуване ім’я, коли застосунок перевіряє один шлях, але використовує інший, або коли привілейована оболонка взаємодіє з inode, який також доступний в іншому місці.

## Hardlink Abuse

Hardlinks створюють кілька імен для одного inode. Вони не вказують на цільовий шлях, як це роблять symlinks; це рівноправні імена одного файлового об’єкта.

Знайдіть SUID-файли з кількома hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Перевірте один підозрілий файл:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Чому це важливо:

- До чутливого файлу можна отримати доступ через менш очевидний шлях.
- SUID wrapper може бути прихований за назвою, яка не виглядає привілейованою.
- Очищення, що видаляє один pathname, може залишити активним інший hardlink.

Сучасні ядра та параметри монтування можуть обмежувати створення hardlink, щоб зменшити цей клас зловживань, але наявні hardlink усе одно варто перевіряти.

## Відновлення видалених файлів через відкриті FD

Якщо процес тримає файл відкритим, дані файлу можуть залишатися доступними навіть після видалення pathname. Linux надає доступ до цих відкритих дескрипторів через `/proc/<pid>/fd/`.

Знайти видалені відкриті файли:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Відновіть дані, якщо права доступу це дозволяють:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Це практичний метод відновлення видалених логів, тимчасових секретів, скинутих бінарних файлів, ротованих файлів або скриптів, видалених після виконання.

## Відновлення ext за допомогою debugfs

У файлових системах ext `debugfs` може перевіряти метадані inode і іноді вивантажувати вміст файлів із образу файлової системи. За можливості працюйте з копією або образом, доступним лише для читання.

Перелічіть записи та перевірте inode:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Створити дамп відомого inode:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Це не гарантує відновлення. Результат залежить від стану файлової системи, того, чи були блоки повторно використані, і чи збереглися метадані. Цей метод усе одно є цінним, оскільки дає змогу перевірити стан на рівні inode, не покладаючись на звичайний обхід шляхів.

## Вичерпання та порядок inode

Вичерпання inode відбувається, коли у файловій системі закінчуються файлові об’єкти, навіть якщо вільне місце на диску ще залишається. Зазвичай це спричиняє збої надійності, але також може пояснити дивну поведінку під час реагування на інциденти або triage у лабораторії.

Перевірте завантаження inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Номери inode та мітки часу також можуть допомогти відтворити активність у простих лабораторних середовищах:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Сприймайте порядок як підказку, а не як доказ. Операції копіювання, розпакування архівів, тип файлової системи, відновлення та паралельний запис можуть змінювати шаблони розподілу.

## Захисні примітки

- Під час аналізу монтуйте невідомі образи лише для читання.
- Зберігайте привілейовані скрипти, service units, plugins і шляхи до helper-програм поза монтуваннями, доступними для запису користувачами.
- Використовуйте `nosuid`, `nodev` і `noexec`, де це операційно доречно, але не сприймайте їх як повноцінний boundary.
- За можливості обмежуйте доступ до `/proc/<pid>/fd`, метаданих процесів і перевірки процесів інших користувачів.
- Відстежуйте точки монтування, доступні для запису, неочікувані hardlinks на привілейовані файли та конфіденційні файли, які видалені, але все ще відкриті.

{{#include ../../banners/hacktricks-training.md}}
