# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3를 사용한 RFID 시스템 공격

적극적으로 유지 관리되는 RRG/Iceman Proxmark3 client와 이에 맞는 firmware를 설치한 다음, 아래에 나온 이전 명령은 변경되었을 수 있으므로 해당 빌드에서 명령 구문을 확인하세요.<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB 공격

MIFARE Classic 1K는 **16개 섹터**로 구성되며, 각 섹터는 **16바이트 블록 4개**로 이루어져 있습니다. 제조업체 블록 0에는 UID/제조업체 데이터가 포함되며, 정품 NXP 카드에서는 읽기 전용입니다. 특수 복제 카드 또는 “magic” 카드는 이 블록을 다시 쓸 수 있는 경우가 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>\
각 섹터에 접근하려면 **2개의 키**(**A** 및 **B**)가 필요하며, 이 키는 각 섹터의 **블록 3**(섹터 trailer)에 저장됩니다. 섹터 trailer에는 두 키를 사용해 **각 블록에 대한 읽기 및 쓰기** 권한을 설정하는 **access bits**도 저장됩니다.\
예를 들어, 첫 번째 키를 알고 있으면 읽기 권한을 부여하고 두 번째 키를 알고 있으면 쓰기 권한을 부여하는 식으로 두 키를 활용할 수 있습니다.

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

Proxmark3를 사용하면 **Tag와 Reader 간 통신을 도청**해 민감한 데이터를 찾아내는 등의 작업도 수행할 수 있습니다. 이 카드의 경우 통신을 스니핑한 다음 사용된 키를 계산할 수 있습니다. **사용된 암호화 연산이 취약**하고 평문과 암호문을 알고 있으면 키를 계산할 수 있기 때문입니다(`mfkey64` tool).<sup>[[3]](#references)</sup>

#### 저장 금액 악용을 위한 MiFare Classic 빠른 워크플로

키 복구, 잔액 차이 분석, 무결성 필드, UID 복제 절차와 Proxmark3 client transcript 및 magic card의 한계에 대한 내용은 [MiFare Classic 오프라인 저장 금액 변조](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1)를 참조하세요.

### Raw Commands

IoT 시스템은 때때로 **브랜드가 없거나 상용 제품이 아닌 태그**를 사용합니다. 이 경우 Proxmark3를 사용해 **태그에 사용자 지정 raw commands**를 보낼 수 있습니다.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

이 정보를 바탕으로 카드와 카드와 통신하는 방법에 관한 정보를 검색해 볼 수 있습니다. Proxmark3에서는 다음과 같이 raw 명령을 전송할 수 있습니다: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 소프트웨어에는 간단한 작업을 수행할 때 사용할 수 있는 **automation scripts** 목록이 미리 포함되어 있습니다. 전체 목록을 확인하려면 `script list` 명령을 사용하세요. 그런 다음 `script run` 명령 뒤에 스크립트 이름을 입력하세요:

```
proxmark3> script run mfkeys
```

tag reader를 **fuzz**하는 스크립트를 만들 수 있습니다. **valid card**의 데이터를 복사한 다음, 하나 이상의 임의 **bytes**를 무작위로 변경하는 **Lua script**를 작성하고 각 반복에서 **reader가 crash**하는지 확인하면 됩니다.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1에 대한 NXP 입장문](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value의 NFC 카드 취약점 악용 (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux 설치](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
