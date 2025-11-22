# Chemin System Path inscriptible +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Si vous trouvez que vous pouvez **écrire dans un dossier du System Path** (notez que cela ne fonctionnera pas si vous pouvez écrire dans un dossier du User Path), il est possible que vous puissiez **escalader les privilèges** sur le système.

Pour cela vous pouvez abuser d'un **Dll Hijacking** où vous allez **détourner une bibliothèque chargée** par un service ou un processus ayant **plus de privilèges** que vous. Et comme ce service charge une Dll qui n'existe probablement même pas sur le système, il va tenter de la charger depuis le System Path où vous pouvez écrire.

Pour plus d'informations sur **ce qu'est Dll Hijackig**, consultez :


{{#ref}}
./
{{#endref}}

## Privesc avec Dll Hijacking

### Trouver une Dll manquante

La première chose dont vous avez besoin est d'**identifier un processus** s'exécutant avec **plus de privilèges** que vous et qui tente de **charger une Dll depuis le System Path** dans lequel vous pouvez écrire.

Le problème dans ce cas est que ces processus tournent probablement déjà. Pour trouver quelles Dlls manquent, vous devez lancer procmon le plus tôt possible (avant que les processus ne soient chargés). Donc, pour trouver les .dll manquantes, faites :

- **Créez** le dossier `C:\privesc_hijacking` et ajoutez le chemin `C:\privesc_hijacking` à la **variable d'environnement System Path**. Vous pouvez le faire **manuellement** ou avec **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Lancez **`procmon`** et allez dans **`Options`** --> **`Enable boot logging`** puis appuyez sur **`OK`** dans l'invite.
- Ensuite, **redémarrez**.
- Quand l'ordinateur a redémarré **`procmon`** commencera à **enregistrer** les événements dès que possible.
- Une fois **Windows** démarré, exécutez **`procmon`** à nouveau ; il vous indiquera qu'il a été en cours d'exécution et **vous demandera si vous voulez enregistrer** les événements dans un fichier. Dites **yes** et **enregistrez les événements dans un fichier**.
- **Après** que le **fichier** est **généré**, **fermez** la fenêtre **`procmon`** ouverte et **ouvrez le fichier d'événements**.
- Ajoutez ces **filtres** et vous trouverez toutes les DLL que certains **processus ont tenté de charger** depuis le dossier System Path inscriptible :

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### DLLs manquantes

En exécutant cela sur une machine Windows 11 virtuelle (vmware) gratuite j'ai obtenu ces résultats :

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Dans ce cas les .exe sont inutiles, ignorez-les ; les DLL manquantes provenaient de :

| Service                         | Dll                | Ligne CMD                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Après avoir trouvé cela, je suis tombé sur ce billet de blog intéressant qui explique aussi comment [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). C'est ce que nous **allons faire maintenant**.

### Exploitation

Ainsi, pour **escalader les privilèges** nous allons détourner la librairie **WptsExtensions.dll**. Ayant le **chemin** et le **nom** il nous suffit de **générer la DLL malveillante**.

Vous pouvez [**try to use any of these examples**](#creating-and-compiling-dlls). Vous pourriez exécuter des payloads tels que : obtenir un rev shell, ajouter un utilisateur, exécuter un beacon...

> [!WARNING]
> Notez que **tous les services ne sont pas exécutés** avec **`NT AUTHORITY\SYSTEM`** ; certains s'exécutent aussi avec **`NT AUTHORITY\LOCAL SERVICE`** qui a **moins de privilèges** et vous **ne pourrez pas créer un nouvel utilisateur** en abusant de ses permissions.\
> Cependant, cet utilisateur possède le privilège **`seImpersonate`**, vous pouvez donc utiliser la[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Donc, dans ce cas un rev shell est une meilleure option que d'essayer de créer un utilisateur.

Au moment de la rédaction, le service **Task Scheduler** s'exécute avec **Nt AUTHORITY\SYSTEM**.

Après avoir **généré la DLL malveillante** (_dans mon cas j'ai utilisé un x64 rev shell et j'ai obtenu une shell en retour mais defender l'a tuée car elle venait de msfvenom_), enregistrez-la dans le System Path inscriptible sous le nom **WptsExtensions.dll** et **redémarrez** l'ordinateur (ou redémarrez le service ou faites ce qu'il faut pour relancer le service/programme affecté).

Quand le service redémarre, la **dll devrait être chargée et exécutée** (vous pouvez **réutiliser** l'astuce **procmon** pour vérifier si la **librairie a été chargée comme prévu**).

{{#include ../../../banners/hacktricks-training.md}}
