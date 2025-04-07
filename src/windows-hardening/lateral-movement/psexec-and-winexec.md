# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Як вони працюють

Процес описаний у наступних кроках, ілюструючи, як маніпулюються бінарні файли служб для досягнення віддаленого виконання на цільовій машині через SMB:

1. **Копіювання бінарного файлу служби до спільного доступу ADMIN$ через SMB** виконується.
2. **Створення служби на віддаленій машині** здійснюється шляхом вказівки на бінарний файл.
3. Служба **запускається віддалено**.
4. Після виходу служба **зупиняється, а бінарний файл видаляється**.

### **Процес ручного виконання PsExec**

Припустимо, що є виконуваний вантаж (створений за допомогою msfvenom і обфусцований за допомогою Veil для уникнення виявлення антивірусом), названий 'met8888.exe', що представляє вантаж meterpreter reverse_http, виконуються наступні кроки:

- **Копіювання бінарного файлу**: Виконуваний файл копіюється до спільного доступу ADMIN$ з командного рядка, хоча його можна розмістити в будь-якому місці файлової системи, щоб залишитися непоміченим.
- Замість копіювання бінарного файлу також можна використовувати бінарний файл LOLBAS, такий як `powershell.exe` або `cmd.exe`, щоб виконувати команди безпосередньо з аргументів. Наприклад, `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **Створення служби**: Використовуючи команду Windows `sc`, яка дозволяє запитувати, створювати та видаляти служби Windows віддалено, створюється служба з назвою "meterpreter", яка вказує на завантажений бінарний файл.
- **Запуск служби**: Останній крок полягає в запуску служби, що, ймовірно, призведе до помилки "time-out" через те, що бінарний файл не є справжнім бінарним файлом служби і не повертає очікуваний код відповіді. Ця помилка не має значення, оскільки основна мета - виконання бінарного файлу.

Спостереження за прослуховувачем Metasploit покаже, що сесія була успішно ініційована.

[Дізнайтеся більше про команду `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Знайдіть більш детальні кроки в: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

- Ви також можете використовувати **бінарний файл Windows Sysinternals PsExec.exe**:

![](<../../images/image (928).png>)

Або отримати доступ до нього через webdav:
```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```
- Ви також можете використовувати [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- Ви також можете використовувати [**SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Ви також можете використовувати **Impacket's `psexec` та `smbexec.py`**.


{{#include ../../banners/hacktricks-training.md}}
