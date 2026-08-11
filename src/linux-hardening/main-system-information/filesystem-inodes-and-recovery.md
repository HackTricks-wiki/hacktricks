# Файлова система, іноди та відновлення

Зловживання файловою системою часто полягає в заплутуванні зв’язку між видимим шляхом і об’єктом, який за ним стоїть.

Образи дисків можуть приховувати іншу файлову систему.<sup>[[1]](#references)</sup> Монтування з правом запису можуть використовуватися привілейованими завданнями.

Жорсткі посилання можуть відкривати доступ до того самого іноду через інше ім’я.<sup>[[3]](#references)</sup> Видалені файли все ще можна читати через відкритий файловий дескриптор.<sup>[[5]](#references)[[6]](#references)</sup>

Ця сторінка зосереджена на техніці, а не на конкретній лабораторній роботі чи цілі.

## Образи дисків і Loop Mounts

Звичайний файл може містити повну файлову систему, тому після монтування образ диска може відкрити дерево другої файлової системи.<sup>[[1]](#references)</sup>

Резервні образи, скопійовані блочні пристрої, артефакти VM або перейменовані blobs можуть містити облікові дані, скрипти, SSH-ключі, конфігураційні файли або flags, навіть якщо зовні вони не здаються корисними.

Визначайте ймовірні образи за допомогою `file` для класифікації кандидата, `blkid` для перевірки розпізнаних метаданих файлової системи та `strings -a` для сканування всього файла на наявність друкованих послідовностей.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Коли монтування дозволено, використовуйте loop mount із `ro`, щоб образ було підключено лише для читання; наведена нижче команда `find` обмежує глибину перевірки та тип файлів.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Якщо монтування недоступне, а образ має формат ext2/ext3/ext4, перевірте його метадані безпосередньо за допомогою `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Ця техніка корисна, оскільки перетворює звичайний на вигляд файл на друге дерево файлової системи.<sup>[[1]](#references)</sup> Розглядайте її як спосіб відновлення прихованих даних, а не як самостійну техніку підвищення привілеїв.

## Writable Mount Abuse

Записуване монтування стає небезпечним, коли привілейованіший контекст згодом довіряє чомусь усередині нього. Важливе питання полягає не лише в тому, «чи можу я сюди записувати?», а й у тому, «хто згодом читає, виконує, імпортує або завантажує звідси?».

Використовуйте `findmnt` для перевірки змонтованих файлових систем і їхніх параметрів.<sup>[[9]](#references)</sup>

Знаходьте записувані монтування та підозрілих споживачів за допомогою задокументованих предикатів `find` для дозволів, типу й меж файлової системи, а потім використовуйте рекурсивний `grep` для пошуку конфігурації ймовірних споживачів.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Поширені шаблони зловживань:

- Завдання cron або service systemd запускає доступний для запису скрипт із mount.<sup>[[13]](#references)[[14]](#references)</sup>
- Привілейований service завантажує plugins, config, templates або helper binaries із mount.
- Mount містить файли SUID і дозволяє їх модифікацію, заміну або маніпуляцію шляхами.
- Контейнер або chroot відкриває шлях, пов’язаний із host, доступний для запису з обмеженого середовища. Mount namespaces надають окремі ієрархії монтування, тоді як `chroot()` лише змінює розв’язання шляхів і не є повноцінним sandbox.<sup>[[15]](#references)[[16]](#references)</sup>

Загальний шаблон перевірки з використанням тих самих предикатів `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Під час доведення впливу в авторизованій лабораторії зберігайте payload спостережуваним і мінімальним, наприклад записуючи вивід `id` у тимчасовий файл.<sup>[[23]](#references)</sup> Основна техніка полягає у відкладеному виконанні через надійне доступне для запису розташування.

## Inodes і плутанина шляхів

Inode — це об’єкт файлової системи; шлях — лише ім’я, що вказує на нього. Метадані пристрою та inode дають змогу розрізняти об’єкти у різних файлових системах, а кількість посилань виявляє кілька жорстких посилань.<sup>[[3]](#references)</sup> Видалене ім’я шляху не завжди означає, що дані зникли, доки процес усе ще має файл відкритим.<sup>[[5]](#references)</sup>

Наведені нижче предикати `find` порівнюють ідентичність inode, кількість посилань, межі пристроїв і часові позначки.<sup>[[4]](#references)</sup>

Порівнюйте файли за inode і пристроєм за допомогою форматів метаданих `ls -i` і `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Знайдіть кожен видимий шлях до того самого inode за допомогою `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Шукайте безпосередньо за номером inode за допомогою `find -inum`, коли у вас є лише метадані.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ця техніка корисна, коли файл має неочікуване ім’я, коли застосунок перевіряє один шлях, але використовує інший, або коли привілейована обгортка взаємодіє з inode, який також доступний в іншому місці.

## Зловживання жорсткими посиланнями

Жорсткі посилання створюють кілька імен для одного inode. На відміну від symbolic links, вони не вказують на цільовий шлях; це рівнозначні імена для одного файлового об’єкта.<sup>[[3]](#references)</sup>

Знаходьте SUID-файли з кількома жорсткими посиланнями за допомогою предикатів `find` для перевірки дозволів і кількості посилань.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Перевірте один підозрілий файл за допомогою `stat` і `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Чому це важливо:

- Чутливий файл може бути доступний через менш очевидний шлях.
- SUID-обгортка може бути прихована за назвою, яка не виглядає привілейованою.
- Очищення, під час якого видаляється один pathname, може залишити активним інший hardlink.

Linux sysctl `fs.protected_hardlinks` може обмежувати створення hardlink між різними рівнями привілеїв.<sup>[[7]](#references)</sup> Наявні hardlink також варто перевіряти.

## Відновлення видалених файлів через відкриті FD

Коли процес утримує файл відкритим, видалення його останнього pathname залишає файл доступним, доки не буде закрито останній дескриптор; Linux надає доступ до цих дескрипторів через `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Знаходьте видалені відкриті файли, переглядаючи дескриптори в `/proc` і фільтруючи вивід відкритих файлів.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Відновлення через ці посилання залежить від дозволів, оскільки розіменування `/proc/<pid>/fd` підпорядковується перевіркам доступу ptrace і дозволам на файли.<sup>[[6]](#references)</sup>

Якщо це дозволено, `readlink` показує ціль дескриптора, а `cp` копіює його вміст.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Це практичний метод відновлення видалених логів, тимчасових секретів, скинутих бінарних файлів, ротованих файлів або скриптів, видалених після виконання.

## Відновлення ext за допомогою debugfs

У файлових системах ext2/ext3/ext4 `debugfs` може перевіряти метадані inode та вивантажувати вміст inode з блокового пристрою або образу; без `-w` він відкриває файлову систему лише для читання.<sup>[[2]](#references)</sup> За можливості працюйте з копією або образом, доступним лише для читання.

Перелічуйте записи та перевіряйте inode за допомогою запитів `debugfs` для перегляду вмісту каталогів, стану inode та перевірки відповідності inode шляху.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Створіть дамп відомого inode за допомогою команди `debugfs dump`, потім визначте тип відновленого виводу за допомогою `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Це не гарантує відновлення. Результат залежить від стану файлової системи, того, чи були блоки повторно використані, і чи збереглися метадані. Для ext3/ext4 у посібнику `debugfs` зазначено, що відновлення видалених inode може завершитися невдачею, оскільки блоки даних звільнених inode більше недоступні.<sup>[[2]](#references)</sup> Ця техніка все одно є цінною, оскільки дає змогу перевіряти стан на рівні inode, не покладаючись на звичайний обхід шляхів.

## Вичерпання inode та впорядкування

Вичерпання inode відбувається, коли у файловій системі закінчуються файлові вузли, навіть якщо на диску ще залишається вільне місце.<sup>[[8]](#references)[[17]](#references)</sup> Зазвичай це спричиняє збої надійності, але також може пояснювати дивну поведінку під час реагування на інциденти або лабораторного тріажу.

Використовуйте `df -i`, щоб отримати інформацію про inode замість інформації про використання блоків.<sup>[[8]](#references)</sup>

Перевірте навантаження на inode за допомогою `df` і підрахунку батьківських каталогів через `find`.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Номери inode та часові мітки також можуть допомогти відновити активність у простих лабораторних середовищах.

Наведені нижче директиви формату `find` відображають ці поля.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Сприймайте порядок як підказку, а не як доказ. Операції копіювання, розпакування архівів, тип файлової системи, відновлення та одночасний запис можуть змінювати шаблони виділення.

## Defensive Notes

- Монтуйте невідомі образи лише для читання під час аналізу.<sup>[[1]](#references)</sup>
- Зберігайте привілейовані скрипти, службові блоки, плагіни та допоміжні шляхи поза монтуваннями, доступними для запису користувачам.
- Використовуйте `nosuid`, `nodev` і `noexec`, де це операційно доцільно; ці параметри вимикають виконання set-ID/можливостей, інтерпретацію пристроїв або безпосереднє виконання бінарних файлів у монтуванні.<sup>[[1]](#references)</sup> Не вважайте їх повноцінним кордоном безпеки.
- Обмежуйте доступ до `/proc/<pid>/fd`; розіменування цих посилань контролюється перевірками доступу ptrace і дозволами файлів.<sup>[[6]](#references)</sup> За можливості обмежуйте ширший доступ до метаданих процесів і перевірку між користувачами.
- Відстежуйте точки монтування, доступні для запису, неочікувані hardlinks на привілейовані файли та конфіденційні файли, які були видалені, але залишаються відкритими.

## References

- [1] [mount(8) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Документація для /proc/sys/fs/ — Документація ядра Linux](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
