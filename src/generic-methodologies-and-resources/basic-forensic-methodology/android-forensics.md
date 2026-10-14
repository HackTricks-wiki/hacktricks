# Analyse forensique Android

{{#include ../../banners/hacktricks-training.md}}

## Appareil verrouillé

Privilégiez les méthodes d’acquisition qui préservent l’état de l’appareil et consignez chaque action. Si l’appareil est verrouillé, les options disponibles dépendent du modèle, de la version d’Android, du niveau de correctifs et de la configuration effectuée avant la saisie. Le NIST recommande de choisir une méthode adaptée à l’appareil et au cadre légal de l’examen.<sup>[[1]](#references)</sup>

- Vérifiez si le débogage USB était activé et si le poste d’acquisition est déjà autorisé. L’accès ADB nécessite normalement que l’utilisateur déverrouille l’appareil et confirme la clé RSA du poste.<sup>[[3]](#references)</sup>
- Déterminez si l’accès biométrique reste disponible au regard des règles légales et procédurales applicables.
- Une **smudge attack** peut révéler un schéma de déverrouillage graphique à partir des traces sur l’écran, bien que les manipulations ultérieures et le nettoyage réduisent sa fiabilité.<sup>[[2]](#references)</sup>
- Si les outils autorisés prennent en charge le modèle et la version logicielle exacts, ils peuvent tenter de retrouver ou de brute force le PIN, le mot de passe ou le schéma. La vérification des identifiants protégée par le matériel, les délais entre les tentatives et les politiques d’effacement rendent cette approche très spécifique à l’appareil. Ne considérez donc pas une technique ou un résultat concernant un iPhone comme une preuve qu’un appareil Android est pris en charge.<sup>[[1]](#references)</sup>

## Acquisition des données

Sur les anciens appareils, une méthode [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) obsolète peut générer un fichier `.backup` que Android Backup Extractor peut décompresser :<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

Ne supposez pas que cela capture toutes les applications. ADB indique que la commande est obsolète, et Android 12 exclut les données des applications ciblant le niveau d’API 31 ou ultérieur, sauf si l’application est débogable.<sup>[[4]](#references)</sup>

### Accès root ou accès physique au débogage

Avec un accès root sur un appareil en fonctionnement, commencez par répertorier les partitions et les montages ; les commandes ci-dessous ne s’appliquent pas directement à une acquisition physique JTAG. Le périphérique bloc approprié dépend du matériel : ne supposez donc pas qu’il s’agit toujours de `mmcblk0`. Créez une image uniquement à partir de la source vérifiée, vers un stockage distinct :<sup>[[1]](#references)</sup>

Une acquisition JTAG utilise plutôt l’interface de test matérielle de l’appareil et un équipement d’acquisition compatible pour lire la mémoire accessible. Le brochage, la prise en charge du chipset, l’état de l’appareil et la distinction entre les cibles volatiles et non volatiles varient selon l’appareil ; documentez le chemin matériel et suivez une procédure validée pour ce modèle.<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

Par exemple, si l’inventaire des partitions confirme que `/dev/block/mmcblk0` correspond à l’intégralité du périphérique flash et que la destination dispose de suffisamment d’espace, la commande d’acquisition originale devient :<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

Ici, `df /data` aide à associer `/data` à son système de fichiers monté ; il ne faut pas le considérer comme une preuve que `mmcblk0` est la bonne source de périphérique complet ni que `4096` est la seule taille de bloc valide pour `dd`.

Calculez le hash du résultat et consignez la commande exacte, les identifiants des périphériques, l'heure et toute modification effectuée pendant l'acquisition.<sup>[[1]](#references)</sup>

### Mémoire

LiME peut acquérir la mémoire physique de Linux et de certains appareils Android, mais son module noyau doit être compilé pour le noyau cible et chargé avec des privilèges suffisants. La signature des modules, le verrouillage du noyau et les mécanismes de sécurité renforcés des versions récentes d'Android peuvent empêcher son chargement.<sup>[[5]](#references)</sup>

La procédure Android du projet envoie le module correspondant avec ADB, redirige un port TCP, charge le module depuis un shell root et capture le flux sur la machine d'examen :<sup>[[5]](#references)</sup>

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

LiME peut aussi écrire sur le stockage de l’appareil avec `path=/sdcard/ram.lime`, mais cela modifie le stockage de l’appareil et nécessite suffisamment d’espace libre. Consignez cet effet secondaire et calculez l’empreinte de l’image acquise.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Lignes directrices sur l’investigation forensique des appareils mobiles](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Attaques par traces sur les écrans tactiles de smartphones](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Restriction des sauvegardes ADB d’Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
