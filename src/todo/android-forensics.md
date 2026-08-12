# Forensics Android

{{#include ../banners/hacktricks-training.md}}

## Appareil verrouillé

Privilégiez les méthodes d'acquisition qui préservent l'état de l'appareil et documentez chaque action. Si l'appareil est verrouillé, les options disponibles dépendent du modèle, de la version d'Android, du niveau de correctifs et de la configuration de l'accès avant la saisie. Le NIST recommande de choisir une méthode en fonction de l'appareil et de l'autorité responsable de l'examen.<sup>[[1]](#references)</sup>

- Vérifiez si le débogage USB était activé et si le poste d'acquisition est déjà autorisé. L'accès ADB nécessite normalement que l'utilisateur déverrouille l'appareil et confirme la clé RSA du poste.<sup>[[3]](#references)</sup>
- Déterminez si l'accès biométrique reste disponible conformément aux règles juridiques et procédurales applicables.
- Une **smudge attack** peut révéler un schéma de déverrouillage graphique à partir des résidus présents sur l'écran, bien que les contacts ultérieurs et le nettoyage en réduisent la fiabilité.<sup>[[2]](#references)</sup>
- Lorsque les outils autorisés prennent en charge exactement l'appareil et sa build logicielle, ils peuvent tenter de récupérer ou de brute force le PIN, le mot de passe ou le schéma. La vérification des identifiants soutenue par le matériel, les délais entre les tentatives et les politiques d'effacement rendent cette opération très dépendante de l'appareil ; ne remplacez donc pas une technique ou un résultat concernant un iPhone par des éléments indiquant qu'un appareil Android est pris en charge.<sup>[[1]](#references)</sup>

## Acquisition des données

Sur les appareils plus anciens, un [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) ancien peut produire un fichier `.backup` qu'Android Backup Extractor peut décompresser :<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
N'assumez pas que cela couvre toutes les applications. ADB indique que la commande est obsolète, et Android 12 exclut les données des applications ciblant le niveau d'API 31 ou ultérieur, sauf si l'application est debuggable.<sup>[[4]](#references)</sup>

### Accès root ou debug physique

Avec un accès root sur un appareil actif, commencez par inventorier les partitions et les montages ; les commandes ci-dessous ne s'appliquent pas directement à une acquisition physique JTAG. Le périphérique bloc correct dépend du matériel ; ne supposez donc pas qu'il s'agit toujours de `mmcblk0`. Imagez uniquement la source vérifiée vers un stockage distinct :<sup>[[1]](#references)</sup>

Une acquisition JTAG utilise plutôt l'interface matérielle de test et d'accès de l'appareil, ainsi qu'un équipement d'acquisition compatible, pour lire la mémoire accessible. Le brochage, la prise en charge du chipset, l'état de l'appareil et la distinction entre les cibles volatiles et non volatiles dépendent de l'appareil ; documentez le chemin matériel et utilisez une procédure validée pour ce modèle.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Par exemple, si l'inventaire des partitions confirme que `/dev/block/mmcblk0` est l'ensemble du périphérique flash et que la destination dispose de suffisamment d'espace, la commande d'acquisition originale devient :<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Ici, `df /data` permet d'associer `/data` à son système de fichiers monté ; il ne doit pas être considéré comme la preuve que `mmcblk0` est la bonne source pour l'ensemble du périphérique ou que `4096` est la seule taille de bloc valide pour `dd`.

Calculez le hash du résultat et consignez la commande exacte, les identifiants du périphérique, l'heure et toute modification effectuée pendant l'acquisition.<sup>[[1]](#references)</sup>

### Mémoire

LiME peut acquérir la mémoire physique à partir de Linux et de certains appareils Android, mais son kernel module doit être compilé pour le kernel cible et chargé avec des privilèges suffisants. La signature des modules, le kernel lockdown et les mécanismes de hardening modernes d'Android peuvent empêcher son chargement.<sup>[[5]](#references)</sup>

Le workflow Android du projet pousse le module correspondant avec ADB, redirige un port TCP, charge le module depuis un root shell et capture le flux sur l'hôte d'examen :<sup>[[5]](#references)</sup>
```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```
LiME peut également écrire sur le stockage de l'appareil avec `path=/sdcard/ram.lime`, mais cela modifie le stockage de l'appareil et nécessite suffisamment d'espace libre. Consignez cet effet secondaire et calculez le hash de l'image acquise.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Directives sur la criminalistique des appareils mobiles](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Attaques Smudge sur les écrans tactiles des smartphones](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restriction des sauvegardes ADB d'Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
