# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara"는 MediaTek의 XFlash download path를 악용하여 DA1 integrity check를 우회하고, 수정된 Download Agent stage 2 (DA2)를 실행합니다. DA1은 DA2의 예상 SHA-256을 RAM에 저장한 뒤, 분기하기 전에 이를 비교합니다. 많은 loader에서 host가 DA2 load address/size를 완전히 제어할 수 있으므로, 이 메모리 write를 검사 없이 수행하여 메모리에 저장된 hash를 덮어쓰고 임의의 payload로 execution을 redirect할 수 있습니다(DA가 cache invalidation을 처리하는 pre-OS context).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary in XFlash (DA1 → DA2)

- **DA1**은 BootROM/Preloader가 sign/load합니다. Download Agent Authorization (DAA)이 활성화된 경우, signed DA1만 실행되어야 합니다.
- **DA2**는 USB를 통해 전송됩니다. DA1은 **size**, **load address**, **SHA-256**을 수신하고, 받은 DA2를 hash한 뒤 이를 **DA1에 내장된 expected hash**(RAM에 복사됨)와 비교합니다.
- **Weakness:** unpatched loader에서 DA1은 DA2 load address/size를 sanitize하지 않으며, expected hash를 메모리에서 write 가능한 상태로 유지하므로 host가 check를 변조할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 staging flow에 진입합니다(DA1이 메모리를 할당하고, DRAM을 준비하며, RAM에서 expected-hash buffer를 노출합니다).
2. **Hash-slot overwrite:** DA1 memory를 scan하여 저장된 DA2-expected hash를 찾고, 이를 attacker-modified DA2의 SHA-256으로 덮어쓰는 작은 payload를 전송합니다. 이는 user-controlled load를 이용해 payload를 hash가 위치한 곳에 기록합니다.
3. **Second `BOOT_TO` + digest:** patched DA2 metadata와 함께 또 다른 `BOOT_TO`을 trigger하고, 수정된 DA2와 일치하는 raw 32-byte digest를 전송합니다. DA1은 수신한 DA2에 대해 SHA-256을 다시 계산하고, 이를 현재 patched된 expected hash와 비교한 후 attacker code로 jump합니다.

영향받는 loader에서 unchecked address와 size는 hash slot을 넘어 attacker가 선택한 pre-OS memory-write primitive를 제공할 수 있습니다. SoC memory map과 이후 verification stages에 따라 early-boot implants, secure-boot-bypass helpers 또는 rootkit-style payloads를 지원할 수 있습니다. DA code execution만으로 persistence 또는 완전한 secure-boot bypass가 자동으로 제공되는 것은 아니며, 별도의 persistence mechanism과 호환되는 verification chain이 여전히 필요합니다.<sup>[[1]](#references)[[2]](#references)</sup>

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
- 16바이트 `payload`는 유료 도구 workflow에서 관찰된 blob과, 공개된 구현이 예상 hash buffer를 patch하는 데 사용하는 blob을 재현합니다. 이는 loader별 동작이며 모든 SoC 또는 DA에 사용할 수 있는 범용 hash-slot patch가 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()`는 hex가 아닌 raw bytes를 전송하므로 DA1이 patched buffer와 비교할 수 있습니다.
- 취약하고 일치하는 loader에서는 DA2가 attacker가 빌드한 image일 수 있으며, 선택한 load metadata가 해당 image의 memory placement를 제어합니다. 잘못된 address는 target을 hang시키거나 손상시킬 수 있으므로 전송 전에 DA/SoC 조합을 검증해야 합니다.<sup>[[3]](#references)</sup>

## Patch 현황 (hardened loaders)

- **관찰된 mitigation**: 연구자들이 조사한 hardened DA는 DA2 load address를 `0x40000000`으로 강제하고 host가 제공한 address를 무시합니다. 따라서 `0x200000` 부근에서 관찰된 DA1 hash region에 대한 write가 방지됩니다. 두 address 모두 architectural constant가 아닌 implementation-specific 값으로 취급해야 합니다.
- **patched DA 감지**: mtkclient/penumbra는 address-hardening을 나타내는 pattern을 DA1에서 scan하며, 발견되면 Carbonara를 건너뜁니다. 구형 DA는 writable hash slot을 노출하며(V5 DA1의 `0x22dea4`와 같은 offset 부근이 일반적), 여전히 exploit할 수 있습니다.
- **V5 vs V6**: 일부 V6 (XML) loader는 여전히 user-supplied address를 허용합니다. 최신 V6 binary는 일반적으로 fixed address를 적용하며, downgrade하지 않는 한 Carbonara에 immune합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) 참고

MediaTek은 Carbonara를 patch했지만, 새로운 vulnerability인 **heapb8**은 patched V6 loader의 DA2 USB file download handler를 target으로 하며 `boot_to`가 hardened된 경우에도 code execution을 제공합니다. 이는 chunked file transfer 중 발생하는 heap overflow를 악용해 DA2 control flow를 장악합니다. 해당 exploit은 Penumbra/mtk-payloads에 공개되어 있으며, Carbonara fix만으로는 모든 DA attack surface가 차단되지 않는다는 점을 보여 줍니다.<sup>[[4]](#references)</sup>

## Triage 및 hardening 참고 사항

- DA2 address/size가 검증되지 않고 DA1이 expected hash를 writable 상태로 유지하는 device는 vulnerable합니다. 이후 Preloader/DA가 address bounds를 적용하거나 hash를 immutable 상태로 유지하면 Carbonara가 mitigation됩니다.
- DAA를 활성화하고 DA1/Preloader가 BOOT_TO parameters(bounds + DA2 authenticity)를 검증하도록 하면 이 primitive가 차단됩니다. hash patch만 차단하고 load를 제한하지 않으면 arbitrary write risk가 여전히 남습니다.

## References

- [1] [Carbonara: MediaTek에서 누구도 제공하지 않은 exploit](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: patched V6 Download Agent exploit](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
