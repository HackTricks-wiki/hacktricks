# Double-fetch d’un buffer utilisateur mappé par MDL sous Windows

{{#include ../../banners/hacktricks-training.md}}

Un pilote du noyau Windows provoque un double-fetch lorsqu’il valide des données dans des pages appartenant à l’appelant, puis transmet un pointeur vers ces mêmes pages à une API sensible du point de vue de la sécurité. Le verrouillage et le mappage des pages ne rendent pas leur contenu immuable. CVE-2025-55680 dans `cldflt.sys` illustre ce schéma : le pilote validait le nom relatif d’un placeholder Cloud Files, puis créait l’objet en continuant à référencer le buffer modifiable de l’appelant.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` crée des fichiers ou des répertoires sous une racine de synchronisation Cloud Files enregistrée. Dans le chemin vulnérable, la modification du nom après sa validation pouvait rediriger une création privilégiée en dehors de cette racine.<sup>[[1]](#references)[[2]](#references)</sup>

## Pourquoi le verrouillage des pages ne verrouillait pas les données

Le chemin vulnérable `HsmpOpCreatePlaceholders()` allouait un MDL pour la charge utile de l’appelant, appelait `ProbeForRead()` et `MmProbeAndLockPages()`, puis mappait ces pages dans l’espace d’adressage virtuel du noyau. Un MDL décrit et verrouille les pages physiques afin qu’elles restent résidentes. Il ne prend **pas** d’instantané de leurs octets. Le mode utilisateur peut donc modifier la même mémoire physique pendant que le pilote la lit via le mappage système.<sup>[[1]](#references)[[3]](#references)</sup>

Le chemin pertinent de la requête et de son utilisation était le suivant :<sup>[[1]](#references)</sup>

1. `cldapi.dll` envoyait le code de contrôle Cloud Files `0x903BC` avec le tag `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) et l’opération de création de placeholders `0xC0000001`.
2. Chaque enregistrement de la charge utile contenait des paires offset/longueur de 16 bits pour le nom relatif et l’identité du fichier. La plupart des champs fixes étaient copiés dans un enregistrement sur la pile, mais le nom de longueur variable restait dans les pages utilisateur mappées.
3. Le pilote parcourait le nom UTF-16 et rejetait toute barre oblique inverse ou deux-points.
4. Il construisait ensuite une `UNICODE_STRING` dont le `Buffer` pointait toujours dans la charge utile mappée et l’assignait à `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` relisait ce pointeur. Un écrivain concurrent pouvait donc faire en sorte que la validation observe une chaîne et que la création du fichier en observe une autre.

Il s’agit d’un **double-fetch**, même si les deux lectures utilisent une adresse virtuelle du noyau : la frontière de sécurité dépend du stockage sous-jacent, et non du mappage virtuel déréférencé par le pilote.<sup>[[1]](#references)</sup>

## Schéma de la race Cloud Files

La stratégie d’exploitation divulguée utilisait des requêtes répétées, des threads mutateurs et une jonction pour transformer le double-fetch en redirection de chemin :<sup>[[1]](#references)</sup>

1. Enregistrer un répertoire contrôlé par l’attaquant avec `CfRegisterSyncRoot()` et y créer `JUSTASTRING` comme jonction vers une destination protégée.
2. Préparer un enregistrement de placeholder partagé avec le nom valide à composant unique `JUSTASTRINGDnewfile.dll`.
3. Faire basculer par des threads mutateurs l’unité de code UTF-16 `D` entre `D` et `\`. La seconde représentation est `JUSTASTRING\newfile.dll`.
4. En parallèle, faire soumettre par des threads de travail des requêtes répétées de création de placeholders référençant la même charge utile, tandis qu’un thread de surveillance vérifie la destination protégée.
5. Lors d’une itération gagnante, la validation observe la représentation sans séparateur, puis la création ultérieure suit la jonction lorsque le nom contient `\`.

Cette primitive permet uniquement de créer un fichier ou un répertoire protégé. Pour obtenir l’exécution de code, il faut encore contrôler le contenu du fichier créé et disposer d’un consommateur privilégié, par exemple une cible adaptée au DLL side-loading. L’analyse originale utilisait cette dernière catégorie de chaîne d’exploitation, mais n’a pas publié le chargeur, la charge utile ni un exploit autonome complet.<sup>[[1]](#references)</sup>

Pour des techniques complémentaires qui élargissent délibérément les races de recherche de chemins sous Windows, voir [Kernel Race Condition Exploitation via Object Manager Slow Paths](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Élévation de privilèges TOCTOU du minifiltre Cloud Files de Microsoft Windows](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - Fonction CfCreatePlaceholders](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - Fonction MmProbeAndLockPages](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
