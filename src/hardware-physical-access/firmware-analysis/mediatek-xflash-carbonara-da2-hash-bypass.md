# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara"는 MediaTek의 XFlash 다운로드 경로를 악용하여 DA1 무결성 검사를 우회하고 수정된 Download Agent stage 2 (DA2)를 실행합니다. DA1은 DA2에 대해 예상되는 SHA-256을 RAM에 저장한 후 분기 전에 비교합니다. 많은 loader에서는 host가 DA2의 load address/size를 완전히 제어할 수 있으므로, 메모리에 기록된 hash를 덮어쓰고 임의의 payload로 실행을 redirect할 수 있는 검증되지 않은 memory write가 발생합니다(DA가 cache invalidation을 처리하는 pre-OS context).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary in XFlash (DA1 → DA2)

- **DA1**은 BootROM/Preloader에 의해 서명되고 load됩니다. Download Agent Authorization (DAA)이 활성화되어 있으면 서명된 DA1만 실행되어야 합니다.
- **DA2**는 USB를 통해 전송됩니다. DA1은 **size**, **load address**, **SHA-256**을 수신하고, 수신한 DA2를 hash한 뒤 DA1에 포함되어 RAM으로 복사된 **expected hash**와 비교합니다.
- **Weakness:** 패치되지 않은 loader에서 DA1은 DA2 load address/size를 sanitize하지 않으며, expected hash를 메모리에서 writable 상태로 유지하므로 host가 해당 check를 변조할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 staging flow에 진입합니다(DA1이 메모리를 할당하고 DRAM을 준비하며 RAM에 있는 expected-hash buffer를 노출합니다).
2. **Hash-slot overwrite:** DA1 memory를 scan하여 저장된 DA2-expected hash를 찾고, 이를 attacker가 수정한 DA2의 SHA-256으로 덮어쓰는 작은 payload를 전송합니다. 이는 user-controlled load를 활용하여 hash가 위치한 곳에 payload를 배치합니다.
3. **Second `BOOT_TO` + digest:** 패치된 DA2 metadata로 또 다른 `BOOT_TO`을 trigger하고, 수정된 DA2와 일치하는 raw 32-byte digest를 전송합니다. DA1은 수신한 DA2에 대해 SHA-256을 다시 계산하고 현재 패치된 expected hash와 비교한 뒤, jump가 성공하여 attacker code로 진입합니다.

load address/size를 attacker가 제어할 수 있으므로 동일한 primitive으로 메모리 어디든 write할 수 있습니다(hash buffer에만 국한되지 않음). 이를 통해 early-boot implant, secure-boot bypass helper 또는 malicious rootkits를 구현할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload`는 DA1 내부의 expected-hash buffer를 패치하는 유료 도구의 blob을 재현합니다.
- `sha256(...).digest()`는 hex가 아닌 raw bytes를 전송하므로 DA1은 패치된 buffer와 비교합니다.
- DA2는 공격자가 빌드한 이미지라면 무엇이든 될 수 있으며, load address/size를 선택하면 DA가 cache invalidation을 처리하면서 임의의 메모리 배치가 가능합니다.<sup>[[3]](#references)</sup>

## 패치 환경 (강화된 loaders)

- **Mitigation**: 업데이트된 DA는 DA2 load address를 `0x40000000`으로 하드코딩하고 host가 제공하는 address를 무시하므로, write가 DA1 hash slot(약 `0x200000` 영역)에 도달할 수 없습니다. hash는 계속 계산되지만 더 이상 공격자가 write할 수 없습니다.
- **패치된 DA 감지**: mtkclient/penumbra는 address-hardening을 나타내는 패턴을 찾기 위해 DA1을 scan하며, 발견되면 Carbonara를 건너뜁니다. 구형 DA는 write 가능한 hash slot(일반적으로 V5 DA1의 `0x22dea4`와 같은 offset 주변)을 노출하므로 여전히 exploit이 가능합니다.
- **V5 vs V6**: 일부 V6 (XML) loaders는 여전히 사용자가 제공한 address를 허용하며, 최신 V6 binaries는 일반적으로 fixed address를 적용하므로 downgrade하지 않는 한 Carbonara에 면역입니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) 참고 사항

MediaTek은 Carbonara를 패치했으며, 더 최신 vulnerability인 **heapb8**은 패치된 V6 loaders의 DA2 USB file download handler를 대상으로 하여 `boot_to`가 harden된 경우에도 code execution을 제공합니다. 이는 chunked file transfer 중 발생하는 heap overflow를 악용해 DA2의 control flow를 장악합니다. 이 exploit은 Penumbra/mtk-payloads에 공개되어 있으며 Carbonara 수정만으로는 모든 DA attack surface가 차단되지 않는다는 점을 보여줍니다.<sup>[[4]](#references)</sup>

## Triage 및 hardening 참고 사항

- DA2 address/size가 검증되지 않고 DA1이 expected hash를 write 가능한 상태로 유지하는 device는 취약합니다. 이후 Preloader/DA가 address bounds를 적용하거나 hash를 immutable 상태로 유지하면 Carbonara가 완화됩니다.
- DAA를 활성화하고 DA1/Preloader가 BOOT_TO parameters(bounds + DA2의 authenticity)를 검증하도록 하면 이 primitive이 차단됩니다. hash patch만 차단하고 load를 제한하지 않으면 arbitrary write risk가 여전히 남습니다.

## References

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
