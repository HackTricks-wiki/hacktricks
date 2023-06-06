## Atacando Sistemas RFID com Proxmark3

O primeiro passo é ter um [**Proxmark3**](https://proxmark.com) e [**instalar o software e suas dependências**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atacando MIFARE Classic 1KB

Ele tem **16 setores**, cada um com **4 blocos** e cada bloco contém **16B**. O UID está no setor 0 bloco 0 (e não pode ser alterado).\
Para acessar cada setor, você precisa de **2 chaves** (**A** e **B**) que são armazenadas no **bloco 3 de cada setor** (trailer do setor). O trailer do setor também armazena os **bits de acesso** que dão as permissões de **leitura e escrita** em **cada bloco** usando as 2 chaves.\
2 chaves são úteis para dar permissões de leitura se você conhece a primeira e de escrita se você conhece a segunda (por exemplo).

Vários ataques podem ser realizados.
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
O Proxmark3 permite realizar outras ações, como **espionar** a **comunicação entre o Tag e o Leitor** para tentar encontrar dados sensíveis. Neste cartão, você pode apenas "farejar" a comunicação e calcular a chave usada, porque as **operações criptográficas usadas são fracas** e, conhecendo o texto simples e o texto cifrado, você pode calculá-la (ferramenta `mfkey64`).

### Comandos Raw

Sistemas IoT às vezes usam **tags não comerciais ou sem marca**. Nesse caso, você pode usar o Proxmark3 para enviar **comandos personalizados para os tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quiting Search
```
Com essa informação, você pode tentar buscar informações sobre o cartão e a forma de se comunicar com ele. O Proxmark3 permite enviar comandos brutos como: `hf 14a raw -p -b 7 26`

### Scripts

O software do Proxmark3 vem com uma lista pré-carregada de **scripts de automação** que você pode usar para realizar tarefas simples. Para recuperar a lista completa, use o comando `script list`. Em seguida, use o comando `script run`, seguido pelo nome do script:
```
proxmark3> script run mfkeys
```
Você pode criar um script para **fuzz tag readers**, copiando os dados de um **cartão válido** e escrevendo um **script Lua** que **randomize** um ou mais **bytes aleatórios** e verifique se o **leitor trava** com qualquer iteração.
