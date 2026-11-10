# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper peut empaqueter un exécutable ou un script dans un fichier Windows Installer (`.msi`). Téléchargez et lancez la version gratuite, puis sélectionnez l’exécutable à empaqueter.<sup>[[3]](#references)</sup> Pour exécuter une séquence de commandes, sélectionnez un fichier `.bat` comme entrée plutôt que d’empaqueter `cmd.exe`.<sup>[[1]](#references)</sup>

![Sélection de l’exécutable source ou du script batch dans MSI Wrapper](<../../images/image (417).png>)

Configurez soigneusement le contexte d’exécution et les autres propriétés de l’installateur :

![Configuration de l’ID de l’application et du contexte de sécurité dans MSI Wrapper](<../../images/image (312).png>)

![Configuration des propriétés de l’installateur dans MSI Wrapper](<../../images/image (346).png>)

![Vérification des paramètres de build de MSI Wrapper](<../../images/image (1072).png>)

Ces valeurs peuvent être modifiées lors de l’empaquetage d’un binaire personnalisé.

Continuez dans les pages restantes de l’assistant et sélectionnez **Build** pour générer l’installateur.<sup>[[1]](#references)</sup>

## Vérifier le contexte d’exécution de la commande encapsulée

Pour un paquet de test, encapsulez un fichier `.bat` qui enregistre son jeton, plutôt que de supposer que le paramètre d’élévation du MSI s’applique à son processus enfant.<sup>[[4]](#references)</sup> Dans l’assistant, choisissez le contexte de sécurité **System** plutôt que **User**, ainsi qu’une installation par machine avec élévation si c’est la méthode prévue.<sup>[[5]](#references)</sup> L’option **System** ne contourne pas l’autorisation : un utilisateur non administrateur a toujours besoin d’une méthode d’installation avec élévation, comme la [mauvaise configuration des deux stratégies `AlwaysInstallElevated`](index.html#alwaysinstallelevated) ou un processus d’installation privilégié.<sup>[[2]](#references)</sup> Choisir **User** exécute plutôt la commande encapsulée dans le contexte de l’utilisateur qui lance l’installation, ce qui peut être nécessaire pour accéder à des ressources spécifiques à l’utilisateur ou au réseau.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Construisez le MSI à partir de ce fichier batch, puis exécutez-le sur l’hôte de test et examinez l’identité et les privilèges enregistrés.<sup>[[4]](#references)</sup> MSI Wrapper associe un code de sortie batch non nul à l’erreur d’installation 1603 ; le code de sortie zéro explicite évite donc un faux échec après un test réussi.<sup>[[4]](#references)</sup> Le fichier de sortie est un artefact de test ; ne déduisez pas une exécution sous SYSTEM du seul succès de `msiexec` ou d’une installation silencieuse.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` masque l’interface de MSI, mais pas nécessairement celle de l’exécutable encapsulé.<sup>[[6]](#references)[[7]](#references)</sup> Pour un installateur encapsulé, définissez dans l’assistant les arguments silencieux pris en charge ; la propriété dynamique `WRAPPED_ARGUMENTS` de MSI Wrapper est une fonctionnalité PRO.<sup>[[1]](#references)[[7]](#references)</sup> Consultez [l’approche des actions personnalisées de WiX](create-msi-with-wix.md) si vous avez besoin d’un contrôle direct sur leur séquencement et l’usurpation d’identité.

> [!WARNING]
> La création d’un MSI n’accorde pas, à elle seule, des privilèges élevés. Le fait que l’installation soit élevée dépend de la stratégie de Windows Installer, du contexte du package et de l’autorisation de l’utilisateur. Microsoft avertit que l’activation de `AlwaysInstallElevated` pour l’utilisateur et l’ordinateur permet aux utilisateurs non-administrateurs d’installer des packages avec des privilèges système.<sup>[[2]](#references)</sup>



## References

- [1] [Documentation de MSI Wrapper - Prise en main](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installation d’un package avec des privilèges élevés pour un utilisateur non-administrateur](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Télécharger](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Créer un MSI à partir d’un fichier batch](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Pages de l’assistant](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Options de ligne de commande](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Arguments de ligne de commande](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
