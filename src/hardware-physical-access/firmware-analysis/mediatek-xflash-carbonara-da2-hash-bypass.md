# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## 요약

"Carbonara"는 MediaTek의 XFlash 다운로드 경로를 악용해 DA1 무결성 검사에도 불구하고 수정된 Download Agent stage 2 (DA2)를 실행합니다. DA1은 RAM에 DA2의 예상 SHA-256을 저장하고 분기 전에 이를 비교합니다. 많은 loader에서는 호스트가 DA2의 load address/size를 완전히 제어할 수 있어, 체크되지 않은 메모리 쓰기가 그 RAM 내의 해시를 덮어쓰고 임의 페이로드로 실행을 리디렉션할 수 있습니다 (OS 전 컨텍스트에서 DA가 cache invalidation을 처리함).

## XFlash의 신뢰 경계 (DA1 → DA2)

- **DA1**은 BootROM/Preloader에 의해 서명/로딩됩니다. Download Agent Authorization (DAA)이 활성화된 경우, 서명된 DA1만 실행되어야 합니다.
- **DA2**는 USB를 통해 전송됩니다. DA1은 **size**, **load address**, 그리고 **SHA-256**을 받고 수신된 DA2의 해시를 계산하여 **DA1에 임베드된(또는 RAM에 복사된) 예상 해시**와 비교합니다.
- **취약점:** 패치되지 않은 loader에서는 DA1이 DA2의 load address/size를 검증하지 않고, 예상 해시를 메모리에서 쓰기 가능 상태로 유지하여 호스트가 검사 값을 변조할 수 있게 합니다.

## Carbonara 흐름 ("two BOOT_TO" 트릭)

1. **First `BOOT_TO`:** DA1→DA2 스테이징 플로우에 진입합니다 (DA1이 DRAM을 할당하고 준비하며, RAM에 예상 해시 버퍼를 노출함).
2. **Hash-slot overwrite:** DA1 메모리에서 저장된 DA2 예상 해시를 스캔하여 공격자가 수정한 DA2의 SHA-256으로 덮어쓰는 작은 payload를 전송합니다. 이는 user-controlled load를 이용해 페이로드를 해시가 위치한 곳에 배치하는 기법입니다.
3. **Second `BOOT_TO` + digest:** 패치된 DA2 메타데이터로 또 다른 `BOOT_TO`를 트리거하고, 수정된 DA2와 일치하는 원시 32-byte digest를 전송합니다. DA1은 수신된 DA2에 대해 SHA-256을 다시 계산하고, 이제 패치된 예상 해시와 비교하여 점프가 성공적으로 공격자 코드로 이어집니다.

load address/size가 attacker-controlled이기 때문에, 동일한 원시(prmitive)는 해시 버퍼뿐만 아니라 메모리의 임의 위치에 쓰기가 가능하여 early-boot implants, secure-boot bypass 도우미, 또는 악성 rootkits 등을 가능하게 합니다.

## Minimal PoC 패턴 (mtkclient-style)
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
- `payload`는 DA1 내부의 expected-hash 버퍼를 패치하는 유료 도구의 blob을 복제합니다.
- `sha256(...).digest()`는 16진수가 아니라 원시 바이트를 전송하므로 DA1이 패치된 버퍼와 비교합니다.
- DA2는 공격자가 만든 임의의 이미지가 될 수 있으며, 로드 주소/크기를 선택하면 임의의 메모리 배치가 가능하고 캐시 무효화는 DA가 처리합니다.

## 트리아지 및 하드닝을 위한 주의사항

- DA2 주소/크기가 검사되지 않고 DA1이 expected hash를 쓰기 가능 상태로 유지되는 장치는 취약합니다. 이후의 Preloader/DA가 주소 범위를 강제하거나 해시를 불변으로 유지하면 Carbonara는 완화됩니다.
- DAA를 활성화하고 DA1/Preloader가 BOOT_TO 파라미터(범위 + DA2의 진위)를 검증하도록 하면 이 프리미티브는 차단됩니다. 로드를 경계 없이 해시 패치만 차단하면 여전히 임의 쓰기 위험이 남습니다.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
