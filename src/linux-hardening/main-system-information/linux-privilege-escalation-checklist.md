# Чекліст підвищення привілеїв у Linux

{{#include ../../banners/hacktricks-training.md}}

# Чекліст — підвищення привілеїв у Linux



### **Найкращий tool для пошуку векторів локального підвищення привілеїв у Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Системна інформація](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Отримати **інформацію про ОС**
- [ ] Перевірити [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), чи є **доступна для запису папка**?
- [ ] Перевірити [**змінні env**](../linux-basics/linux-privilege-escalation/index.html#env-info), чи містять вони чутливі дані?
- [ ] Шукати [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **за допомогою scripts** (DirtyCow?)
- [ ] Перед запуском kernel PoC перевірити його **фактичні prerequisites**, а не лише `uname -r`: архітектуру, необхідні опції/модулі `CONFIG_*`, створення namespace та активні mitigations. Наприклад, перевірити доступність user/network namespace за допомогою `unshare -Urn true`; сучасні netfilter exploits можуть вимагати `CONFIG_USER_NS`, непривілейовані user namespaces і `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Перевірити**, чи є [**версія sudo** вразливою](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg**: перевірка підпису не вдалася](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Перевірити [**помилкові налаштування kernel module і завантаження модулів**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, enforcement підписів і `modules_disabled`.
- [ ] Перевірити [**шляхи зловживання kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), якщо шлях до helper можна змінити або викликати.
- [ ] Перевірити [**доступні для запису шляхи /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), зокрема доступні для запису файли `.ko*` і метадані `modules.*`.
- [ ] Додаткова системна enum-інформація ([date, статистика системи, інформація про cpu, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Перерахувати додаткові defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Диски](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Перелічити змонтовані** диски
- [ ] **Є немонтований диск?**
- [ ] **Є creds у fstab?**

### [**Встановлене ПЗ**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Перевірити наявність**[ **корисного ПЗ**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **серед встановленого**
- [ ] **Перевірити наявність** [**вразливого ПЗ**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **серед встановленого**
- [ ] У Debian/Ubuntu перевірити, чи встановлено/увімкнено **сканування інтерпретаторів needrestart**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Вразливі збірки перетинали межу привілеїв, повторно використовуючи контрольовані attacker-ом `PYTHONPATH`/`RUBYLIB`, виконуючи race з `/proc/<pid>/exe` або скануючи контрольовані attacker-ом шляхи Perl, коли APT чи `unattended-upgrades` запускали needrestart від root.<sup>[[4]](#references)</sup>

### [Процеси](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Запущено невідоме **ПЗ**?
- [ ] Чи працює якесь ПЗ з **більшими привілеями, ніж повинно**?
- [ ] Шукати **exploits запущених процесів** (особливо для запущеної версії).
- [ ] Чи можна **змінити binary** якогось запущеного процесу?
- [ ] **Моніторити процеси** та перевіряти, чи часто запускається якийсь цікавий процес.
- [ ] Чи можна **прочитати** пам’ять якогось цікавого **процесу** (де можуть зберігатися паролі)?

### [Заплановані/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Чи змінюється [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)якимось cron і чи можна в нього **писати**?
- [ ] Є [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)у cron job?
- [ ] Чи **виконується** якийсь [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)або чи знаходиться він усередині **modifiable folder**?
- [ ] Чи виявлено, що якийсь **script** може або вже [**виконується** дуже **часто**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (кожні 1, 2 або 5 хвилин)

### [Сервіси](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Є **доступний для запису .service** файл?
- [ ] Є **доступний для запису binary**, який виконується **сервісом**?
- [ ] Є доступний для запису **helper, config або environment file, на який посилається root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Перевірити об’єднаний unit за допомогою `systemctl cat <unit>` і переглянути [зловживання service/socket файлами](../interesting-files-permissions/write-to-root.md).
- [ ] Є **доступна для запису папка в systemd PATH**?
- [ ] Є **доступний для запису systemd unit drop-in** у `/etc/systemd/system/<unit>.d/*.conf`, який може перевизначити `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Є **доступний для запису timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Є **доступний для запису .socket** файл?
- [ ] Чи можна **взаємодіяти з будь-яким socket**?
- [ ] **HTTP sockets** із цікавою інформацією?
- [ ] Чи можна отримати доступ до [**API container-runtime або node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), наприклад `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` або endpoint kubelet? Перевірити raw HTTP/gRPC API, навіть якщо звичайний CLI відсутній.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Чи можна **взаємодіяти з будь-яким D-Bus**?

### [Мережа](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу, щоб визначити, де ви перебуваєте
- [ ] **Відкриті порти, до яких раніше не було доступу**, після отримання shell усередині машини?
- [ ] Чи можна **перехоплювати трафік** за допомогою `tcpdump`?

### [Користувачі](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Загальна **enum-інформація** про користувачів/групи
- [ ] Чи маєте ви **дуже великий UID**? Чи є **машина** **вразливою**?
- [ ] Чи можна [**підвищити привілеї завдяки групі**](../user-information/interesting-groups-linux-pe/index.html), до якої ви належите?
- [ ] Дані **clipboard**?
- [ ] Password Policy?
- [ ] Спробувати **використати** кожен **відомий пароль**, який раніше вдалося знайти, для входу **під кожним** можливим **користувачем**. Також спробувати увійти без пароля.

### [Доступний для запису PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Якщо у вас є **права запису до якоїсь папки в PATH**, це може дозволити підвищити привілеї

### [Команди SUDO та SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Чи можна виконати **будь-яку команду через sudo**? Чи можна використати її для READ, WRITE або EXECUTE чогось від root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Якщо `sudo -l` дозволяє `sudoedit`, перевірити **ін’єкцію аргументів sudoedit** (CVE-2023-22809) через `SUDO_EDITOR`/`VISUAL`/`EDITOR`, щоб редагувати довільні файли у вразливих версіях (`sudo -V` < 1.9.12p2). Приклад: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Є **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Чи обмежені [команди **sudo** **шляхом**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)? Чи можна **обійти ці обмеження**?
- [ ] [**Sudo/SUID binary без указаного шляху**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary із указаним шляхом**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Обхід
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Відсутня .so library у SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) у доступній для запису папці?
- [ ] [**SUID RPATH/RUNPATH або доступний для запису шлях до library**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Доступні SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Чи можна створити SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Чи можна [**прочитати або змінити файли sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Чи можна [**змінити /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Команда [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Чи має якийсь binary **неочікувану capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Чи має якийсь файл **неочікувану ACL**?

### [Відкриті shell-сесії](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Передбачуваний PRNG OpenSSL — CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Цікаві значення конфігурації SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Цікаві файли](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** — прочитати чутливі дані? Записати для privesc?
- [ ] **Файли passwd/shadow** — прочитати чутливі дані? Записати для privesc?
- [ ] **Перевірити загальновідомі цікаві папки** на наявність чутливих даних
- [ ] **Файли в незвичних місцях/власником яких є інший користувач,** до яких ви можете отримати доступ або змінити executable files
- [ ] **Змінені** протягом останніх хвилин
- [ ] **Файли Sqlite DB**
- [ ] **Приховані файли**
- [ ] **Script/Binaries у PATH**
- [ ] **Web files** (паролі?)
- [ ] **Backups**?
- [ ] **Відомі файли, що містять паролі**: використати **Linpeas** і **LaZagne**
- [ ] **Загальний пошук**

### [**Доступні для запису файли**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Змінити python library**, щоб виконати довільні команди?
- [ ] Чи можна **змінювати log files**? Exploit **Logtotten**
- [ ] Чи можна **змінювати /etc/sysconfig/network-scripts/**? Exploit для Centos/Redhat
- [ ] Чи можна [**записувати в ini, int.d, systemd або rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Інші tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Чи можна [**зловживати NFS для підвищення привілеїв**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Чи потрібно [**вийти з restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Рекомендації Sudo: редагування довільних файлів через sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Документація Oracle Linux: конфігурація systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: вимоги до exploit і дослідження CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Рекомендації з безпеки Qualys: LPE у needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
