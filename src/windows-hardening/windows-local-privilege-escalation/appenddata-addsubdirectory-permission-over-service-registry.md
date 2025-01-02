{{#include ../../banners/hacktricks-training.md}}

**Le post original est** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Résumé

Deux clés de registre ont été trouvées comme étant modifiables par l'utilisateur actuel :

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Il a été suggéré de vérifier les permissions du service **RpcEptMapper** en utilisant l'**interface regedit**, spécifiquement l'onglet **Permissions Effectives** de la fenêtre **Paramètres de Sécurité Avancés**. Cette approche permet d'évaluer les permissions accordées à des utilisateurs ou groupes spécifiques sans avoir besoin d'examiner chaque Entrée de Contrôle d'Accès (ACE) individuellement.

Une capture d'écran a montré les permissions attribuées à un utilisateur à faibles privilèges, parmi lesquelles la permission **Créer Sous-clé** était notable. Cette permission, également appelée **AppendData/AddSubdirectory**, correspond aux résultats du script.

L'incapacité à modifier certaines valeurs directement, tout en ayant la capacité de créer de nouvelles sous-clés, a été notée. Un exemple mis en avant était une tentative de modifier la valeur **ImagePath**, qui a entraîné un message d'accès refusé.

Malgré ces limitations, un potentiel d'escalade de privilèges a été identifié grâce à la possibilité d'exploiter la sous-clé **Performance** dans la structure de registre du service **RpcEptMapper**, une sous-clé qui n'est pas présente par défaut. Cela pourrait permettre l'enregistrement de DLL et la surveillance des performances.

La documentation sur la sous-clé **Performance** et son utilisation pour la surveillance des performances a été consultée, conduisant au développement d'une DLL de preuve de concept. Cette DLL, démontrant l'implémentation des fonctions **OpenPerfData**, **CollectPerfData**, et **ClosePerfData**, a été testée via **rundll32**, confirmant son succès opérationnel.

L'objectif était de contraindre le **service RPC Endpoint Mapper** à charger la DLL Performance conçue. Les observations ont révélé qu'exécuter des requêtes de classe WMI liées aux Données de Performance via PowerShell entraînait la création d'un fichier journal, permettant l'exécution de code arbitraire sous le contexte **SYSTEM LOCAL**, accordant ainsi des privilèges élevés.

La persistance et les implications potentielles de cette vulnérabilité ont été soulignées, mettant en évidence sa pertinence pour les stratégies de post-exploitation, le mouvement latéral et l'évasion des systèmes antivirus/EDR.

Bien que la vulnérabilité ait été initialement divulguée de manière non intentionnelle par le biais du script, il a été souligné que son exploitation est limitée aux versions Windows obsolètes (par exemple, **Windows 7 / Server 2008 R2**) et nécessite un accès local.

{{#include ../../banners/hacktricks-training.md}}
