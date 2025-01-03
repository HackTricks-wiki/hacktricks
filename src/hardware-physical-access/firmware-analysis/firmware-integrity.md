{{#include ../../banners/hacktricks-training.md}}

## Intégrité du Firmware

Le **firmware personnalisé et/ou les binaires compilés peuvent être téléchargés pour exploiter les failles de vérification d'intégrité ou de signature**. Les étapes suivantes peuvent être suivies pour la compilation d'un shell de liaison backdoor :

1. Le firmware peut être extrait en utilisant firmware-mod-kit (FMK).
2. L'architecture et l'endianness du firmware cible doivent être identifiées.
3. Un compilateur croisé peut être construit en utilisant Buildroot ou d'autres méthodes appropriées pour l'environnement.
4. La backdoor peut être construite en utilisant le compilateur croisé.
5. La backdoor peut être copiée dans le répertoire /usr/bin du firmware extrait.
6. Le binaire QEMU approprié peut être copié dans le rootfs du firmware extrait.
7. La backdoor peut être émulée en utilisant chroot et QEMU.
8. La backdoor peut être accessible via netcat.
9. Le binaire QEMU doit être supprimé du rootfs du firmware extrait.
10. Le firmware modifié peut être reconditionné en utilisant FMK.
11. Le firmware avec backdoor peut être testé en l'émulant avec l'outil d'analyse de firmware (FAT) et en se connectant à l'IP et au port de la backdoor cible en utilisant netcat.

Si un shell root a déjà été obtenu par analyse dynamique, manipulation du bootloader ou test de sécurité matériel, des binaires malveillants précompilés tels que des implants ou des shells inversés peuvent être exécutés. Des outils automatisés de payload/implant comme le framework Metasploit et 'msfvenom' peuvent être utilisés en suivant les étapes suivantes :

1. L'architecture et l'endianness du firmware cible doivent être identifiées.
2. Msfvenom peut être utilisé pour spécifier le payload cible, l'IP de l'hôte attaquant, le numéro de port d'écoute, le type de fichier, l'architecture, la plateforme et le fichier de sortie.
3. Le payload peut être transféré sur l'appareil compromis et s'assurer qu'il a les permissions d'exécution.
4. Metasploit peut être préparé pour gérer les demandes entrantes en démarrant msfconsole et en configurant les paramètres selon le payload.
5. Le shell inversé meterpreter peut être exécuté sur l'appareil compromis.

{{#include ../../banners/hacktricks-training.md}}
