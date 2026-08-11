# Forensics Android

{{#include ../banners/hacktricks-training.md}}

## Appareil verrouillé

Privilégiez les méthodes d'acquisition qui préservent l'état de l'appareil et documentez chaque action. Si l'appareil est verrouillé, les options disponibles dépendent du modèle, de la version d'Android, du niveau de correctif et de la configuration de l'accès avant la saisie. Le NIST recommande de choisir une méthode adaptée à l'appareil et à l'autorité chargée de l'examen.<sup>[[1]](#references)</sup>

- Vérifiez si le débogage USB était activé et si le poste d'acquisition est déjà autorisé. L'accès ADB exige normalement que l'utilisateur déverrouille l'appareil et confirme la clé RSA du poste.<sup>[[3]](#references)</sup>
- Déterminez si l'accès biométrique reste disponible conformément aux règles juridiques et procédurales applicables.
- Une **smudge attack** peut révéler un schéma de déverrouillage graphique à partir des résidus présents sur l'écran, bien que les touchers ultérieurs et le nettoyage réduisent sa fiabilité.<sup>[[2]](#references)</sup>
- Utilisez des outils commerciaux ou de recherche de contournement du verrouillage uniquement s'ils prennent explicitement en charge l'appareil et le build logiciel exacts.

## Acquisition des données

Sur les appareils plus anciens, un [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) legacy peut produire un fichier `.backup` qu'Android Backup Extractor peut décompresser :<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Ne supposez pas que cela couvre toutes les applications. ADB indique que la commande est obsolète, et Android 12 exclut les données des applications ciblant le niveau d’API 31 ou ultérieur, sauf si l’application est debuggable.<sup>[[4]](#references)</sup>

### Accès root ou debug physique

Avec un accès root sur un appareil actif, commencez par recenser les partitions et les points de montage ; les commandes ci-dessous ne s’appliquent pas directement à une acquisition physique JTAG. Le périphérique bloc correct dépend du matériel ; ne supposez donc pas qu’il s’agit toujours de `mmcblk0`. Imagez uniquement la source vérifiée vers un stockage distinct :<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Hachez le résultat et consignez la commande exacte, les identifiants de l’appareil, l’heure et toute modification effectuée pendant l’acquisition.<sup>[[1]](#references)</sup>

### Mémoire

LiME peut acquérir la mémoire physique de Linux et de certains appareils Android, mais son module du kernel doit être compilé pour le kernel cible et chargé avec des privilèges suffisants. La signature des modules, le kernel lockdown et les mesures de hardening modernes d’Android peuvent empêcher son chargement.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Directives sur la forensics des appareils mobiles](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Attaques Smudge sur les écrans tactiles des smartphones](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restriction des sauvegardes ADB d’Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Extracteur de mémoire Linux (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Extracteur de sauvegardes Android](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
