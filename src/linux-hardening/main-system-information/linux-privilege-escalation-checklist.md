# Чекліст підвищення привілеїв у Linux

{{#include ../../banners/hacktricks-training.md}}

# Чекліст - підвищення привілеїв у Linux



### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Інформація про систему](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), чи є **доступна для запису папка**?
- [ ] Перевірити [**змінні середовища**](../linux-basics/linux-privilege-escalation/index.html#env-info), чи є конфіденційні дані?
- [ ] Шукати [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **за допомогою скриптів** (DirtyCow?)
- [ ] Перед запуском kernel PoC перевірити його **фактичні передумови**, а не лише `uname -r`: архітектуру, необхідні параметри/модулі `CONFIG_*`, створення namespace та активні mitigations. Наприклад, перевірити доступність user/network namespace за допомогою `unshare -Urn true`; сучасні netfilter exploits можуть вимагати `CONFIG_USER_NS`, непривілейовані user namespaces і `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Перевірити**, чи є [**версія sudo вразливою**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Не вдалася перевірка підпису**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed) **Dmesg**
- [ ] Перевірити [**помилкові налаштування kernel module і завантаження модулів**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, контроль підписів і `modules_disabled`.
- [ ] Перевірити [**шляхи зловживання kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), якщо шлях helper можна змінити або викликати.
- [ ] Перевірити [**шляхи `/lib/modules`, доступні для запису**](kernel-modules-and-modprobe.md#writable-libmodules-review), включно з файлами `.ko*` і метаданими `modules.*`, доступними для запису.
- [ ] Додаткова enum системи ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Перерахувати додаткові захисти](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Диски](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Перелічити змонтовані** диски
- [ ] **Є незмонтований диск?**
- [ ] **Є creds у fstab?**

### [**Встановлене ПЗ**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Перевірити наявність**[ **корисного ПЗ**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **серед встановленого**
- [ ] **Перевірити наявність** [**вразливого ПЗ**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **серед встановленого**
- [ ] У Debian/Ubuntu перевірити, чи встановлено/увімкнено **сканування інтерпретаторів needrestart**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Вразливі збірки перетинали межу привілеїв, повторно використовуючи контрольовані attacker-ом `PYTHONPATH`/`RUBYLIB`, створюючи race condition для `/proc/<pid>/exe` або скануючи контрольовані attacker-ом шляхи Perl, коли APT або `unattended-upgrades` запускали needrestart від імені root.<sup>[[4]](#references)</sup>

### [Процеси](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Запущено якесь **невідоме ПЗ**?
- [ ] Чи працює якесь ПЗ із **вищими привілеями, ніж повинно**?
- [ ] Шукати **exploits запущених процесів** (особливо для запущеної версії).
- [ ] Чи можна **змінити binary** будь-якого запущеного процесу?
- [ ] **Моніторити процеси** й перевірити, чи часто запускається якийсь цікавий процес.
- [ ] Чи можна **читати** пам'ять якогось цікавого **процесу** (де можуть зберігатися паролі)?

### [Заплановані/Cron-завдання?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи змінюється [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)якимось cron, і чи можна **записувати** в нього?
- [ ] Є [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)у cron-завданні?
- [ ] Чи **виконується** якийсь [**скрипт, доступний для зміни** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink), або чи розташований він у **папці, доступній для зміни**?
- [ ] Чи виявлено, що якийсь **скрипт** може або вже [**виконується** дуже **часто**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (кожні 1, 2 або 5 хвилин)

### [Сервіси](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Є файл **.service, доступний для запису**?
- [ ] Є **binary, доступний для запису**, який запускається **сервісом**?
- [ ] Є доступний для запису **helper, config або environment file, на який посилається root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Перевірити об'єднаний unit за допомогою `systemctl cat <unit>` і переглянути [зловживання service/socket file](../interesting-files-permissions/write-to-root.md).
- [ ] Є **папка в PATH systemd, доступна для запису**?
- [ ] Є **drop-in systemd unit, доступний для запису**, у `/etc/systemd/system/<unit>.d/*.conf`, який може перевизначити `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Є **timer, доступний для запису**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Є файл **.socket, доступний для запису**?
- [ ] Чи можна **взаємодіяти з будь-яким socket**?
- [ ] Є **HTTP sockets** із цікавою інформацією?
- [ ] Чи можна отримати доступ до [**API container-runtime або node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), такого як `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` або endpoint kubelet? Перевірити raw HTTP/gRPC API, навіть якщо звичайний CLI відсутній.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Чи можна **взаємодіяти з будь-яким D-Bus**?

### [Мережа](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу, щоб визначити своє місцезнаходження
- [ ] **Відкриті порти, до яких раніше не було доступу**, після отримання shell усередині машини?
- [ ] Чи можна **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Виконати загальне **перерахування користувачів/груп**
- [ ] Є **дуже великий UID**? Чи є **машина** **вразливою**?
- [ ] Чи можна [**підвищити привілеї завдяки групі**](../user-information/interesting-groups-linux-pe/index.html), до якої ви належите?
- [ ] Дані **Clipboard**?
- [ ] Політика паролів?
- [ ] Спробувати **використати** кожен **відомий пароль**, який раніше було знайдено, для входу **під кожним** можливим **користувачем**. Також спробувати увійти без пароля.

### [PATH, доступний для запису](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права на запис у папку з PATH**, це може дозволити підвищити привілеї

### [Команди SUDO і SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можна виконати **будь-яку команду через sudo**? Чи можна використати її, щоб READ, WRITE або EXECUTE щось від імені root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Якщо `sudo -l` дозволяє `sudoedit`, перевірити **ін'єкцію аргументів sudoedit** (CVE-2023-22809) через `SUDO_EDITOR`/`VISUAL`/`EDITOR`, щоб редагувати довільні файли у вразливих версіях (`sudo -V` < 1.9.12p2). Приклад: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Є **експлуатований SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи [**обмежені команди** **sudo** **шляхом**? Чи можна **обійти обмеження**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary без указаного шляху**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary із указаним шляхом**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Обійти
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Відсутня .so library у SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) у папці, доступній для запису?
- [ ] [**SUID RPATH/RUNPATH або шлях до library, доступний для запису**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Доступні SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можна створити SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можна [**прочитати або змінити файли sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можна [**змінити `/etc/ld.so.conf.d/`**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Команда [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Має якийсь binary **неочікувану capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Має якийсь файл **неочікувану ACL**?

### [Відкриті Shell-сесії](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Передбачуваний PRNG OpenSSL - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Цікаві значення конфігурації SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Цікаві файли](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Файли профілів** - Прочитати конфіденційні дані? Записати для privesc?
- [ ] **Файли passwd/shadow** - Прочитати конфіденційні дані? Записати для privesc?
- [ ] **Перевірити загальновідомі цікаві папки** на наявність конфіденційних даних
- [ ] **Файли в нетипових місцях/файли, якими володіють інші,** до яких ви можете отримати доступ або змінити executable files
- [ ] **Змінені** за останні хвилини
- [ ] **Файли Sqlite DB**
- [ ] **Приховані файли**
- [ ] **Script/Binaries у PATH**
- [ ] **Web-файли** (паролі?)
- [ ] **Backups**?
- [ ] **Відомі файли, що містять паролі**: використати **Linpeas** і **LaZagne**
- [ ] **Загальний пошук**

### [**Файли, доступні для запису**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Змінити python library**, щоб виконати довільні команди?
- [ ] Чи можна **змінювати log files**? Exploit **Logtotten**
- [ ] Чи можна **змінити `/etc/sysconfig/network-scripts/`**? Exploit для Centos/Redhat
- [ ] Чи можна [**записувати в ini, int.d, systemd або rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Інші tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Чи можна [**зловживати NFS для підвищення привілеїв**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно [**вийти з restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Рекомендації Sudo: редагування довільного файла через sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Документація Oracle Linux: конфігурація drop-in systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: вимоги exploit і дослідження CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Рекомендації з безпеки Qualys: LPE у needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
