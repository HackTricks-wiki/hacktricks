# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara"는 MediaTek의 XFlash 다운로드 경로를 악용해 DA1의 무결성 검사를 우회하고 수정된 Download Agent stage 2(DA2)를 실행합니다. DA1은 DA2의 기대되는 SHA-256 값을 RAM에 저장하고 분기하기 전에 이를 비교합니다. 많은 로더에서는 호스트가 DA2의 로드 주소/크기를 완전히 제어할 수 있어, 검증되지 않은 메모리 쓰기가 그 메모리 내 해시를 덮어쓰고 임의 페이로드로 실행을 리디렉션할 수 있습니다(OS 이전 컨텍스트이며 캐시 무효화는 DA가 처리함).

## Trust boundary in XFlash (DA1 → DA2)

- **DA1**은 BootROM/Preloader에 의해 서명되어 로드됩니다. Download Agent Authorization(DAA)이 활성화되어 있으면, 서명된 DA1만 실행되어야 합니다.
- **DA2**는 USB를 통해 전송됩니다. DA1은 **size**, **load address**, 그리고 **SHA-256**을 수신하고 수신한 DA2를 해시한 뒤 **DA1에 내장된(그리고 RAM으로 복사된) 기대 해시**와 비교합니다.
- **약점:** 패치되지 않은 로더에서는 DA1이 DA2의 로드 주소/크기를 검사(sanitize)하지 않고 기대 해시를 메모리에서 쓰기 가능 상태로 유지하여, 호스트가 이 검사를 조작할 수 있습니다.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 스테이징 플로우에 진입합니다(DA1이 DRAM을 할당·준비하고 RAM에 있는 기대 해시 버퍼를 노출시킵니다).
2. **Hash-slot overwrite:** 작은 페이로드를 보내 DA1 메모리에서 저장된 DA2 기대 해시를 스캔하고, 공격자가 수정한 DA2의 SHA-256으로 이를 덮어씁니다. 이는 사용자 제어 로드를 이용해 페이로드를 해시가 존재하는 위치에 착지시키는 방식입니다.
3. **Second `BOOT_TO` + digest:** 패치된 DA2 메타데이터로 또 다른 `BOOT_TO`를 트리거하고 수정된 DA2와 일치하는 raw 32-byte 다이제스트를 전송합니다. DA1은 수신한 DA2에 대해 SHA-256을 재계산하고, 이제 패치된 기대 해시와 비교하여 점프가 공격자 코드로 성공합니다.

로드 주소/크기가 공격자가 제어 가능하므로, 동일한 원시(prmitive)는 해시 버퍼뿐 아니라 메모리의 임의 위치에 쓰기가 가능하여 초기 부트 임플란트, secure-boot 우회 보조, 또는 악성 루트킷 등을 구현할 수 있습니다.

## Minimal PoC pattern (mtkclient-style)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- `payload`는 DA1 내부의 expected-hash 버퍼를 패치하는 유료 툴 블랍(blob)을 복제합니다.
- `sha256(...).digest()`는 raw bytes(헥스가 아님)를 전송하므로 DA1이 패치된 버퍼와 비교합니다.
- DA2는 공격자가 만든 어떤 이미지라도 될 수 있으며; 로드 주소/크기를 선택하면 임의의 메모리 배치가 가능하고 캐시 무효화는 DA가 처리합니다.

## 패치 현황 (hardened loaders)

- **완화**: 업데이트된 DA들은 DA2 로드 주소를 `0x40000000`로 하드코딩하고 호스트가 제공한 주소를 무시하여 쓰기가 DA1 해시 슬롯(~0x200000 영역)에 도달할 수 없습니다. 해시는 여전히 계산되지만 더 이상 공격자가 쓸 수 없습니다.
- **패치된 DA 감지**: mtkclient/penumbra는 주소 하드닝을 나타내는 패턴을 DA1에서 검사합니다; 발견되면 Carbonara는 건너뜁니다. 오래된 DA는 쓰기 가능한 해시 슬롯(보통 V5 DA1의 `0x22dea4` 같은 오프셋 주변)을 노출하며 계속 악용 가능합니다.
- **V5 vs V6**: 일부 V6 (XML) 로더는 여전히 사용자 제공 주소를 허용합니다; 최신 V6 바이너리는 보통 고정 주소를 강제하여 다운그레이드되지 않는 한 Carbonara에 면역입니다.

## Post-Carbonara (heapb8) 메모

MediaTek는 Carbonara를 패치했습니다; 더 새로운 취약점인 **heapb8**은 패치된 V6 로더의 DA2 USB 파일 다운로드 핸들러를 겨냥하며, `boot_to`가 하드닝되어 있어도 코드 실행을 제공합니다. 이 취약점은 청크 단위 파일 전송 중 발생하는 힙 오버플로를 악용하여 DA2의 제어 흐름을 탈취합니다. 익스플로잇은 Penumbra/mtk-payloads에 공개되어 있으며 Carbonara 수정만으로는 모든 DA 공격 표면이 봉인되지 않음을 보여줍니다.

## 분류 및 하드닝을 위한 참고사항

- DA2 주소/크기가 검증되지 않고 DA1이 expected-hash를 쓰기 가능 상태로 유지하는 장치는 취약합니다. 이후 Preloader/DA가 주소 경계(또는 해시를 불변으로 유지)를 강제하면 Carbonara는 완화됩니다.
- DAA를 활성화하고 DA1/Preloader가 BOOT_TO 매개변수(경계 + DA2의 진위)를 검증하도록 하면 이 프리미티브를 차단합니다. 로드 범위를 제한하지 않고 해시 패치만 차단하면 여전히 임의 쓰기 위험이 남습니다.

## 참고자료

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
