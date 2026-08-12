# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper peut empaqueter un exécutable ou un script dans un fichier Windows Installer (`.msi`). Téléchargez et démarrez l’édition gratuite, puis sélectionnez l’exécutable à empaqueter.<sup>[[3]](#references)</sup> Pour exécuter une séquence de commandes, sélectionnez un fichier `.bat` comme entrée au lieu d’empaqueter `cmd.exe`.<sup>[[1]](#references)</sup>

![Sélection de l’exécutable source ou du script batch dans MSI Wrapper](<../../images/image (417).png>)

Configurez soigneusement le contexte d’exécution et les autres propriétés de l’installeur :

![Configuration de l’ID de l’application et du contexte de sécurité dans MSI Wrapper](<../../images/image (312).png>)

![Configuration des propriétés de l’installeur dans MSI Wrapper](<../../images/image (346).png>)

![Vérification des paramètres de build de MSI Wrapper](<../../images/image (1072).png>)

Ces valeurs peuvent être modifiées lors de l’empaquetage d’un binaire personnalisé.

Continuez sur les pages restantes de l’assistant, puis sélectionnez **Build** pour générer l’installeur.<sup>[[1]](#references)</sup>

> [!WARNING]
> La création d’un MSI n’accorde pas à elle seule des privilèges élevés. Le fait que l’installation soit élevée dépend de la stratégie de Windows Installer, du contexte du package et de l’autorisation de l’utilisateur. Microsoft avertit que l’activation de `AlwaysInstallElevated` pour l’utilisateur et l’ordinateur permet aux utilisateurs non administrateurs d’installer des packages avec des privilèges système.<sup>[[2]](#references)</sup>

## References

- [1] [Documentation de MSI Wrapper - Premiers pas](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installer un package avec des privilèges élevés pour un utilisateur non administrateur](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Téléchargement](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
