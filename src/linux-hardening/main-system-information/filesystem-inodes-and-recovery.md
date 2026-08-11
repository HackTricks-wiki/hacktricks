# Файлова система, іноди та відновлення

{{#include ../../banners/hacktricks-training.md}}

Зловживання файловою системою часто полягає в тому, щоб заплутати взаємозв’язок між видимим шляхом і об’єктом, який за ним стоїть.

Образи дисків можуть приховувати іншу файлову систему.<sup>[[1]](#references)</sup> Доступні для запису монтування можуть використовуватися привілейованими завданнями.

Hardlinks можуть відкривати доступ до того самого inode через інше ім’я.<sup>[[3]](#references)</sup> Видалені файли все ще можуть бути доступними для читання через відкритий файловий дескриптор.<sup>[[5]](#references)[[6]](#references)</sup>

Ця сторінка зосереджена на техніці, а не на конкретній лабораторній роботі чи цілі.

## Образи дисків і монтування через loop

Звичайний файл може містити повну файлову систему, тому образ диска після монтування може відкрити дерево другої файлової системи.<sup>[[1]](#references)</sup>

Резервні образи, скопійовані блокові пристрої, артефакти VM або перейменовані blobs можуть містити облікові дані, скрипти, SSH-ключі, конфігураційні файли або flags, навіть якщо ззовні вони не здаються корисними.

Визначайте ймовірні образи за допомогою `file`, щоб класифікувати кандидат, `blkid`, щоб перевірити розпізнані метадані файлової системи, і `strings -a`, щоб просканувати весь файл на наявність друкованих послідовностей.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Коли монтування дозволено, використовуйте loop mount із `ro`, щоб образ було під’єднано лише для читання; наведена нижче команда `find` обмежує глибину перевірки та тип файлів.<sup>[[1]](#references)[[4]](#references)</sup>
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
Ця техніка корисна, оскільки перетворює файл зі звичайним виглядом на друге дерево файлової системи.<sup>[[1]](#references)</sup> Розглядайте її як спосіб відновлення прихованих даних, а не як самостійну ескалацію привілеїв.

## Зловживання доступним для запису монтуванням

Монтована файлова система, доступна для запису, стає небезпечною, коли привілейованіший контекст згодом довіряє чомусь усередині неї. Важливо запитувати не лише «чи можу я сюди записувати?», а й «хто згодом читає, виконує, імпортує або завантажує звідси?».

Використовуйте `findmnt`, щоб перевірити змонтовані файлові системи та їхні параметри.<sup>[[9]](#references)</sup>

Знаходьте монтування, доступні для запису, і підозрілих споживачів за допомогою задокументованих предикатів `find` для дозволів, типу та меж файлової системи, а потім використовуйте рекурсивний `grep` для пошуку конфігурації ймовірних споживачів.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Поширені шаблони зловживань:

- Завдання cron або служба systemd запускає скрипт із монтування, доступний для запису.<sup>[[13]](#references)[[14]](#references)</sup>
- Привілейована служба завантажує plugins, config, templates або helper binaries із монтування.
- Монтування містить файли SUID і дозволяє їх змінювати, замінювати або маніпулювати шляхами.
- Контейнер або chroot надає доступ до шляху на хості, доступного для запису з обмеженого середовища. Простори імен монтувань забезпечують окремі ієрархії монтувань, тоді як `chroot()` лише змінює визначення шляхів і не є повноцінною sandbox.<sup>[[15]](#references)[[16]](#references)</sup>

Загальний шаблон перевірки з використанням тих самих предикатів `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Під час доведення впливу в авторизованій лабораторії зберігайте payload спостережуваним і мінімальним, наприклад записуючи вивід `id` у тимчасовий файл.<sup>[[23]](#references)</sup> Основна техніка полягає у відкладеному виконанні через надійне доступне для запису розташування.

## Inodes і плутанина шляхів

Inode — це об’єкт файлової системи; шлях — лише ім’я, що вказує на нього. Метадані пристрою та inode дають змогу розрізняти об’єкти між файловими системами, а кількість посилань виявляє кілька hard links.<sup>[[3]](#references)</sup> Видалений pathname не завжди означає, що дані зникли, якщо процес усе ще тримає файл відкритим.<sup>[[5]](#references)</sup>

Наведені нижче предикати `find` порівнюють ідентичність inode, кількість посилань, межі пристроїв і часові мітки.<sup>[[4]](#references)</sup>

Порівнюйте файли за inode і пристроєм за допомогою форматів метаданих `ls -i` і `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Знайти кожне видиме ім’я шляху для того самого inode за допомогою `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Виконуйте пошук безпосередньо за номером inode за допомогою `find -inum`, коли у вас є лише метадані.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ця техніка корисна, коли файл має неочікуване ім’я, коли застосунок перевіряє один шлях, але використовує інший, або коли привілейована обгортка взаємодіє з inode, який також доступний в іншому місці.

## Hardlink Abuse

Hardlinks створюють кілька імен для одного inode. Вони не вказують на цільовий шлях, як symlinks; це рівнозначні імена одного й того самого файлового об’єкта.<sup>[[3]](#references)</sup>

Знаходьте SUID-файли з кількома hardlinks за допомогою предикатів `find` для прав доступу та кількості посилань.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Перевірте один підозрілий файл за допомогою `stat` і `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Чому це важливо:

- Конфіденційний файл може бути доступний через менш очевидний шлях.
- SUID-обгортка може бути прихована за назвою, яка не виглядає привілейованою.
- Очищення, яке видаляє один шлях, може залишити інше hardlink-посилання активним.

Linux sysctl `fs.protected_hardlinks` може обмежувати створення hardlink-посилань між межами привілеїв.<sup>[[7]](#references)</sup> Наявні hardlink-посилання все одно потребують перевірки.

## Відновлення видалених файлів через відкриті FD

Коли процес утримує файл відкритим, видалення його останнього шляху залишає файл доступним, доки не буде закрито останній дескриптор; Linux надає доступ до цих дескрипторів через `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Знайти видалені відкриті файли можна, перелічивши дескриптори в `/proc` і відфільтрувавши вивід відкритих файлів.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Відновлення через ці посилання залежить від наявності дозволів, оскільки розіменування `/proc/<pid>/fd` підпорядковується перевіркам доступу ptrace та дозволам на файли.<sup>[[6]](#references)</sup>

Якщо це дозволено, `readlink` показує ціль дескриптора, а `cp` копіює його вміст.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Це практична техніка для відновлення видалених журналів, тимчасових секретів, скинутих бінарних файлів, ротованих файлів або скриптів, видалених після виконання.

## Відновлення ext за допомогою debugfs

У файлових системах ext2/ext3/ext4 `debugfs` може перевіряти метадані inode і видобувати вміст inode з блочного пристрою або образу; без `-w` він відкриває файлову систему лише для читання.<sup>[[2]](#references)</sup> За можливості працюйте з копією або образом, доступним лише для читання.

Перелічуйте записи та перевіряйте inode за допомогою запитів `debugfs` для отримання списків каталогів, статусу inode і перевірки відповідності inode шляху.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Створіть дамп відомого inode за допомогою команди `debugfs dump`, а потім класифікуйте відновлений вивід за допомогою `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Це не гарантує відновлення. Результат залежить від стану файлової системи, того, чи були блоки повторно використані, і того, чи все ще існують метадані. Для ext3/ext4 посібник `debugfs` зазначає, що відновлення видалених inode може завершитися невдало, оскільки блоки даних звільнених inode більше недоступні.<sup>[[2]](#references)</sup> Ця техніка все одно є цінною, оскільки дає змогу перевіряти стан на рівні inode без використання звичайного проходження шляхами.

## Вичерпання inode та порядок

Вичерпання inode відбувається, коли у файловій системі закінчуються файлові вузли, навіть якщо вільне місце на диску ще залишається.<sup>[[8]](#references)[[17]](#references)</sup> Зазвичай це спричиняє збої надійності, але також може пояснювати незвичну поведінку під час реагування на інциденти або тріажу в лабораторії.

Використовуйте `df -i`, щоб отримати інформацію про inode замість інформації про використання блоків.<sup>[[8]](#references)</sup>

Перевіряйте навантаження на inode за допомогою `df` і підрахунку батьківських каталогів через `find`.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Номери inode і часові мітки також можуть допомогти відновити активність у простих лабораторних середовищах.

Наведені нижче директиви формату `find` відкривають доступ до цих полів.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Сприймайте порядок як підказку, а не як доказ. Операції копіювання, розпакування архівів, тип файлової системи, відновлення та паралельні записи можуть змінювати шаблони виділення.

## Захисні примітки

- Монтуйте невідомі образи лише для читання під час аналізу.<sup>[[1]](#references)</sup>
- Зберігайте привілейовані скрипти, службові блоки, плагіни та допоміжні шляхи поза монтуваннями, доступними для запису користувачам.
- Використовуйте `nosuid`, `nodev` і `noexec`, якщо це операційно доцільно; ці параметри вимикають виконання set-ID/можливостей, інтерпретацію пристроїв або безпосереднє виконання бінарних файлів у змонтованій файловій системі.<sup>[[1]](#references)</sup> Не розглядайте їх як повноцінний бар’єр.
- Обмежуйте доступ до `/proc/<pid>/fd`; розіменування цих посилань контролюється перевірками доступу ptrace та дозволами на файли.<sup>[[6]](#references)</sup> За можливості обмежуйте ширший доступ до метаданих процесів і перевірку між користувачами.
- Відстежуйте точки монтування, доступні для запису, неочікувані жорсткі посилання на привілейовані файли та конфіденційні файли, які видалено, але залишаються відкритими.

## References

- [1] [mount(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Документація для /proc/sys/fs/ — документація ядра Linux](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
