# Чекліст - підвищення привілеїв у Linux

{{#include ../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку локальних векторів підвищення привілеїв у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Інформація про систему](privilege-escalation/index.html#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](privilege-escalation/index.html#path), чи є якась **папка з правом запису**?
- [ ] Перевірити [**env variables**](privilege-escalation/index.html#env-info), чи є якісь чутливі деталі?
- [ ] Шукати [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **за допомогою скриптів** (DirtyCow?)
- [ ] **Перевірити**, чи версія [**sudo** вразлива](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Більше системної енумерації ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Перелічити можливі захисти](privilege-escalation/index.html#enumerate-possible-defenses)

### [Диски](privilege-escalation/index.html#drives)

- [ ] **Перерахувати змонтовані** диски
- [ ] **Є незмонтований диск?**
- [ ] **Є якісь креденшіали в fstab?**

### [**Встановлене програмне забезпечення**](privilege-escalation/index.html#installed-software)

- [ ] **Перевірити**, чи встановлено [**корисне програмне забезпечення**](privilege-escalation/index.html#useful-software)
- [ ] **Перевірити**, чи встановлено [**вразливе програмне забезпечення**](privilege-escalation/index.html#vulnerable-software-installed)

### [Процеси](privilege-escalation/index.html#processes)

- [ ] Чи запущене будь-яке **невідоме програмне забезпечення**?
- [ ] Чи якесь ПЗ працює з **більшими правами, ніж повинно**?
- [ ] Шукати **експлойти для запущених процесів** (особливо за версією).
- [ ] Чи можете ви **змінити бінарник** якогось запущеного процесу?
- [ ] **Моніторити процеси** і перевірити, чи якийсь цікавий процес запускається часто.
- [ ] Чи можете ви **прочитати** пам'ять цікавого **процесу** (де можуть зберігатися паролі)?

### [Заплановані/cron задачі?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи модифікується [**PATH** ](privilege-escalation/index.html#cron-path) якимось cron і чи ви можете в нього **записувати**?
- [ ] Є якийсь [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)в cron job?
- [ ] Чи виконується якийсь [**змінюваний скрипт** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) або він знаходиться в **папці з правом редагування**?
- [ ] Ви помітили, що якийсь **скрипт** може/виконується **дуже часто** (кожні 1, 2 або 5 хвилин)? (frequent cron jobs)

### [Сервіси](privilege-escalation/index.html#services)

- [ ] Є **записуваний .service** файл?
- [ ] Є **записуваний бінарник**, який виконується як **service**?
- [ ] Є **записувана папка в systemd PATH**?
- [ ] Є **записуваний systemd unit drop-in** в `/etc/systemd/system/<unit>.d/*.conf`, який може перевизначити `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Є якийсь **записуваний timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Є **записуваний .socket** файл?
- [ ] Чи можете ви **спілкуватися з будь-яким сокетом**?
- [ ] **HTTP sockets** з цікавою інформацією?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Чи можете ви **спілкуватися з будь-яким D-Bus**?

### [Мережа](privilege-escalation/index.html#network)

- [ ] Проведіть енумерацію мережі, щоб дізнатися, де ви знаходитеся
- [ ] **Відкриті порти, до яких ви не мали доступу** до отримання шеллу на машині?
- [ ] Чи можете ви **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](privilege-escalation/index.html#users)

- [ ] Загальна енумерація користувачів/груп
- [ ] У вас дуже великий **UID**? Чи **вразлива** машина?
- [ ] Чи можете ви [**підвищити привілеї завдяки групі**](privilege-escalation/interesting-groups-linux-pe/index.html), до якої належите?
- [ ] **Дані буфера обміну**?
- [ ] Політика паролів?
- [ ] Спробуйте **використати** кожен **відомий пароль**, який ви знайшли раніше, щоб увійти **під кожним** можливим **користувачем**. Спробуйте також увійти без пароля.

### [Записуваний PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права запису в якусь папку з PATH**, ви можете підвищити привілеї

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можете ви виконувати **будь-яку команду через sudo**? Чи можете ви використати це для READ, WRITE або EXECUTE чогось від імені root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Якщо `sudo -l` дозволяє `sudoedit`, перевірте на **sudoedit argument injection** (CVE-2023-22809) через `SUDO_EDITOR`/`VISUAL`/`EDITOR` для редагування довільних файлів на вразливих версіях (`sudo -V` < 1.9.12p2). Приклад: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Чи є якийсь **експлуатований SUID бінарник**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи обмежені [**sudo** команди **через path**? чи можете ви **обійти** обмеження](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Відсутність .so бібліотеки в SUID бінарнику**](privilege-escalation/index.html#suid-binary-so-injection) з папки з правом запису?
- [ ] [**Доступні SUDO tokens**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можете ви створити SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можете ви [**прочитати або змінити sudoers файли**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можете ви [**змінити /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) команда

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Чи має будь-який бінарник якісь **неочікувані capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Чи має якийсь файл **неочікуваний ACL**?

### [Відкриті shell-сесії](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Цікаві файли](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Прочитати чутливі дані? Запис для privesc?
- [ ] **passwd/shadow files** - Прочитати чутливі дані? Запис для privesc?
- [ ] **Перевірити поширені цікаві папки** на наявність чутливих даних
- [ ] **Дивні/Належні файли,** до яких ви можете мати доступ або змінити виконувані файли
- [ ] **Змінені** за останні хвилини
- [ ] **Sqlite DB files**
- [ ] **Приховані файли**
- [ ] **Скрипти/Бінарники в PATH**
- [ ] **Веб-файли** (паролі?)
- [ ] **Бекапи**?
- [ ] **Відомі файли, що містять паролі**: використовуйте **Linpeas** та **LaZagne**
- [ ] **Загальний пошук**

### [**Записувані файли**](privilege-escalation/index.html#writable-files)

- [ ] **Змінити python-бібліотеку** для виконання довільних команд?
- [ ] Чи можете ви **змінити log файли**? **Logtotten** експлойт
- [ ] Чи можете ви **змінити /etc/sysconfig/network-scripts/**? Centos/Redhat експлойт
- [ ] Чи можете ви [**записувати в ini, init.d, systemd or rc.d файли**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Інші фішки**](privilege-escalation/index.html#other-tricks)

- [ ] Чи можете ви [**зловживати NFS для підвищення привілеїв**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно вам [**втекти з обмеженого шеллу**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Посилання

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
