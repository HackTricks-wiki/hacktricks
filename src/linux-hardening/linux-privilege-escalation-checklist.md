# Контрольний список - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Отримати **OS information**
- [ ] Перевірити [**PATH**](privilege-escalation/index.html#path), чи є **записувана папка**?
- [ ] Перевірити [**env variables**](privilege-escalation/index.html#env-info), чи є чутливі дані?
- [ ] Шукати [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **за допомогою скриптів** (DirtyCow?)
- [ ] **Перевірити**, чи є вразливість у версії [**sudo**](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Більше системної енумерації ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Перелічити більше механізмів захисту](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Перелік змонтованих** дисків
- [ ] **Є незмонтований диск?**
- [ ] **Є креденшелли в fstab?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Перевірити**, чи встановлено [**корисне ПО**](privilege-escalation/index.html#useful-software)
- [ ] **Перевірити**, чи встановлено [**вразливе ПО**](privilege-escalation/index.html#vulnerable-software-installed)

### [Processes](privilege-escalation/index.html#processes)

- [ ] Чи запускається якесь **невідоме ПО**?
- [ ] Чи якесь ПО працює з **більшими привілеями, ніж потрібно**?
- [ ] Шукати **експлойти для запущених процесів** (особливо за версією).
- [ ] Чи можна **змінити бінарник** будь-якого запущеного процесу?
- [ ] **Моніторити процеси** і перевіряти, чи запускається якийсь цікавий процес часто.
- [ ] Чи можна **прочитати** пам'ять цікавого **процесу** (де можуть зберігатися паролі)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи змінюється [**PATH**](privilege-escalation/index.html#cron-path) якимось cron і чи можете ви **записувати** в нього?
- [ ] Чи є [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) у cron job?
- [ ] Чи виконується або знаходиться в **записуваній папці** якийсь [**змінюваний скрипт**](privilege-escalation/index.html#cron-script-overwriting-and-symlink)?
- [ ] Ви виявили, що якийсь **скрипт** може або виконується [**дуже часто**](privilege-escalation/index.html#frequent-cron-jobs)? (кожну 1, 2 або 5 хвилин)

### [Services](privilege-escalation/index.html#services)

- [ ] Є **записуваний .service** файл?
- [ ] Є **записуваний бінарник**, який виконується **сервісом**?
- [ ] Є **записувана папка в systemd PATH**?
- [ ] Є **записуваний systemd unit drop-in** в `/etc/systemd/system/<unit>.d/*.conf`, який може перевизначити `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Є **записуваний timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Є **записуваний .socket** файл?
- [ ] Чи можете ви **спілкуватися з якимось socket**?
- [ ] **HTTP sockets** з цікавою інформацією?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Чи можете ви **спілкуватися з якимось D-Bus**?

### [Network](privilege-escalation/index.html#network)

- [ ] Енумерувати мережу, щоб знати, де ви
- [ ] **Відкриті порти, до яких ви не мали доступу** до того, як отримали shell на машині?
- [ ] Чи можете ви **сніффити трафік** за допомогою `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Загальна енумерація користувачів/груп
- [ ] Чи у вас дуже великий UID? Чи **вразлива** машина?
- [ ] Чи можете ви [**ескалювати привілеї завдяки групі**](privilege-escalation/interesting-groups-linux-pe/index.html), до якої належите?
- [ ] Дані **Clipboard**?
- [ ] Політика паролів?
- [ ] Спробуйте **використати** кожен **відомий пароль**, який ви знайшли, щоб увійти **під кожним** можливим **користувачем**. Спробуйте також увійти без пароля.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права запису в якусь папку в PATH**, ви можете підняти привілеї

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можете ви виконати **якусь команду через sudo**? Чи можна її використати для ЧИТАННЯ, ЗАПИСУ або ВИКОНАННЯ чогось як root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Якщо `sudo -l` дозволяє `sudoedit`, перевірте на **sudoedit argument injection** (CVE-2023-22809) через `SUDO_EDITOR`/`VISUAL`/`EDITOR` для редагування довільних файлів на вразливих версіях (`sudo -V` < 1.9.12p2). Приклад: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Чи є якийсь **експлуатований SUID бінарник**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи обмежені [**sudo** команди шляхом PATH? чи можна **обійти** обмеження](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Обхід
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Відсутність .so бібліотеки в SUID бінарнику**](privilege-escalation/index.html#suid-binary-so-injection) з папки, у яку можна записувати?
- [ ] [**Доступні SUDO токени**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можна створити SUDO токен**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можете ви [**прочитати або змінити sudoers файли**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можете ви [**змінити /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) команда

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Чи має якийсь бінарник **неочікувану capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Чи має якийсь файл **неочікуваний ACL**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Читання чутливих даних? Запис для privesc?
- [ ] **passwd/shadow files** - Читання чутливих даних? Запис для privesc?
- [ ] **Перевірити поширені цікаві папки** на наявність чутливих даних
- [ ] **Дивні розташування/власні файли,** до яких ви можете мати доступ або змінювати виконувані файли
- [ ] **Змінені** за останні хвилини
- [ ] **Sqlite DB files**
- [ ] **Приховані файли**
- [ ] **Скрипти/Бінарники в PATH**
- [ ] **Веб-файли** (паролі?)
- [ ] **Резервні копії**?
- [ ] **Відомі файли, що містять паролі**: Використовуйте **Linpeas** і **LaZagne**
- [ ] **Загальний пошук**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Змінити python бібліотеку** для виконання довільних команд?
- [ ] Чи можна **змінити лог-файли**? Експлойт **Logtotten**
- [ ] Чи можна **змінити /etc/sysconfig/network-scripts/**? Експлойт для Centos/Redhat
- [ ] Чи можете ви [**записувати в ini, init.d, systemd або rc.d файли**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Чи можна [**зловживати NFS для ескалації привілеїв**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно вам [**втекти з обмеженого shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Посилання

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
