# Open vSwitch forwarded-skb marker 제거로 인한 ESP page-cache 쓰기

{{#include ../../../banners/hacktricks-training.md}}

유용한 Linux kernel exploitation 패턴은 **skb에서 소유권 메타데이터를 세탁하되 외부 fragment는 제거하지 않은 채**, 해당 skb를 데이터를 제자리에서 쓰는 consumer로 전달하는 것입니다. Open vSwitch (OVS)의 경우, userspace upcall이 실패하면 아직 살아 있는 `MSG_ZEROCOPY` skb에서 `SKBFL_SHARED_FRAG`가 지워집니다. 이후 ESP가 읽기 전용 파일의 page-cache folio에 직접 복호화 데이터를 씁니다. 이로 인해 결정론적인 로컬 page-cache 쓰기가 발생하며, CVE-2026-90049, CVE-2026-89487, CVE-2026-80977을 통해 추적되었습니다.<sup>[[1]](#references)[[2]](#references)</sup>

이는 전통적인 memory corruption이 아니라 Copy Fail/Dirty Frag 유형의 문제입니다. race나 address disclosure가 필요 없고, 파일은 읽을 수 있기만 하면 됩니다. 변경된 바이트는 디스크가 아닌 page cache에 존재합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## 보안 불변 조건: 외부 fragment에는 표시가 유지되어야 함

`SKBFL_SHARED_FRAG`는 skb fragment가 자신이 단독 소유하지 않은 storage를 참조할 수 있음을 제자리에서 데이터를 쓰는 consumer에 알립니다. ESP fast path인 `esp_input()`은 `skb_has_shared_frag()`가 false일 때만 nonlinear하고 복제되지 않은 skb를 제자리에서 복호화할 수 있습니다. 그렇지 않으면 `skb_cow_data()`가 먼저 private storage를 만듭니다. 이 consumer 측 검사는 Dirty Frag 이후 추가되었습니다.<sup>[[5]](#references)</sup>

따라서 불변 조건은 서로 독립적인 두 부분으로 구성됩니다.<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. 제자리에서 데이터를 쓰는 writer는 `SKBFL_SHARED_FRAG`를 검사하고, 변경 전에 공유 데이터를 복사해야 합니다.
2. 모든 clone, coalesce, transfer 또는 forwarding 경로는 외부 page가 연결된 동안 해당 표시를 유지해야 합니다.

Fragnesia는 `skb_try_coalesce()`에서 fragment descriptor를 옮기는 과정에서 두 번째 규칙을 위반했습니다. OVS 경로는 미묘하게 다릅니다. fragment를 전혀 옮기지 않고, **원본 skb에서 표시를 제자리에서 지운 다음 계속 forwarding합니다**.<sup>[[2]](#references)[[4]](#references)</sup>

## 권한 없는 사용자의 OVS 접근 가능성

OVS의 kernel datapath는 `ovs_datapath`, `ovs_vport`, `ovs_flow`, `ovs_packet` 같은 generic-netlink family를 통해 제어됩니다. 상태를 변경하는 작업에는 namespace를 인식하는 `GENL_UNS_ADMIN_PERM`이 사용되므로, `unshare -Urn` 환경에서 실행되는 프로세스는 자체 network namespace 안에 datapath를 만들고, veth를 연결하고, flow action을 설치하는 데 필요한 `CAP_NET_ADMIN`을 얻습니다. OVS family를 확인하는 과정에서 `openvswitch.ko`가 자동으로 로드될 수도 있습니다. 이 공격 표면을 이용하는 데 host의 `CAP_SYS_MODULE`, `ovs-vsctl`, `ovs-vswitchd`는 필요하지 않습니다.<sup>[[2]](#references)[[7]](#references)</sup>

중요한 차이는 두 가지 upcall 유형에 있습니다.<sup>[[2]](#references)[[7]](#references)</sup>

- **flow miss**는 packet을 `ovs-vswitchd`로 보냅니다. upcall이 실패하면 packet은 보통 drop됩니다.
- 명시적인 `OVS_ACTION_ATTR_USERSPACE` action은 빌린 복사본을 지정된 port ID로 보낸 다음, 원본 skb에 후속 action을 실행합니다.

따라서 공격자는 다음과 같은 형태의 flow를 설치할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

선택된 port ID를 소유한 listener가 없어 userspace action은 예측 가능한 방식으로 실패하지만, 이어지는 `OUTPUT` action은 원래 패킷을 계속 유지합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Root cause: 살아남는 패킷에 대한 `skb_tx_error()`

취약한 OVS upcall 오류 경로는 `skb_tx_error(skb)`를 호출합니다. 이 helper는 실패한 transmit 이후 skb가 해제되는 상황을 위해 설계되었습니다. 이 helper는 `skb_zcopy_clear()`를 통해 zerocopy bookkeeping을 완료하는데, 해당 함수의 flag mask는 과거에 `SKBFL_SHARED_FRAG`도 제거했습니다. OVS는 userspace-action 오류를 무시하고 action list를 계속 실행하여 helper의 수명 계약을 위반했습니다.<sup>[[1]](#references)[[2]](#references)</sup>

악용 가능한 상태 전이는 다음과 같습니다.<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

이 방식은 `skb_zcopy()`가 zerocopy 상태를 찾을 때만 작동합니다. `SKBFL_SHARED_FRAG`만 포함된 fragment로는 충분하지 않습니다. `MSG_ZEROCOPY`는 `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG`를 설정하고 `SKBFL_DONT_ORPHAN`도 설정하므로 유용합니다. 후자는 OVS userspace copy 중 `skb_orphan_frags()`가 foreign pages를 교체하지 않도록 합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## write primitive 빌드

end-to-end trigger는 다음 요소로 구성됩니다.<sup>[[2]](#references)[[3]](#references)</sup>

1. `unshare -Urn`으로 private user 및 network namespaces에 진입합니다.
2. `PROT_READ | MAP_SHARED`로 읽을 수 있는 대상 파일을 매핑합니다.
3. 별도의 sender netns와 veth pair를 사용합니다. 로컬 loopback은 빌린 페이지를 복사해 primitive를 무효화합니다.
4. OVS datapath와 실패하는 `USERSPACE`-then-`OUTPUT` flow를 빌드합니다.
5. `rfc4106(gcm(aes))`와 UDP port 4500을 사용하는 transport-mode ESP-in-UDP XFRM state를 설치합니다.
6. `[ESP header | mapped file bytes | invalid ICV]` 형태의 iovec를 사용하는 `MSG_ZEROCOPY` datagram을 하나 전송합니다.

XFRM state는 AES-128-GCM keying material 20바이트를 사용합니다. 앞의 16바이트는 AES key이고, 뒤의 4바이트는 RFC 4106 salt입니다. 선택한 8바이트 explicit IV의 경우, payload confidentiality는 counter block `salt || IV || be32(2)`로 시작합니다. 반면 counter 값 1은 authentication result를 마스킹하는 데 사용됩니다.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

OVS가 marker를 제거하면 ESP는 no-copy 경로를 사용해 파일 기반 fragment에 `plaintext = ciphertext XOR keystream`을 적용합니다. 인증은 이 변환 **후에** 확인되므로, 모두 0인 유효하지 않은 ICV로 인해 패킷이 `-EBADMSG`로 실패하는 시점에는 page-cache 바이트가 이미 변경된 상태입니다.<sup>[[2]](#references)</sup>

### GCM을 원하는 바이트로 변환하기

현재 바이트가 `C`이고 원하는 바이트가 `P`라면, 첫 번째 payload keystream 바이트는 `C XOR P`여야 합니다. AES key와 salt를 고정한 상태에서 explicit IV의 16비트 suffix를 순회하고, 가능한 각 첫 번째 keystream 바이트에 대해 suffix 하나를 미리 계산합니다:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

공개 구현은 ciphertext를 32바이트로 제한하고, 패킷마다 파일 fragment를 1바이트씩 이동합니다. 선택한 첫 바이트는 이전 패킷의 첫 collateral byte를 덮어씁니다. 매 패킷 전에 `pread()`로 `C`를 새로 읽고, 값이 같은 바이트는 건너뛰며, 마지막 패킷은 요청된 범위를 넘어서 쓰지 않도록 길이를 줄입니다. 따라서 256개 항목의 lookup table을 사용하면, 값이 다른 바이트마다 대략 패킷 하나를 전송해 byte 단위로 원하는 콘텐츠를 page cache에 쓸 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Page-cache write to root

실용적인 표적은 기존 setuid-root 실행 파일입니다. PoC는 첫 160바이트를 고정 주소의 읽기/실행 `PT_LOAD` 하나와 `PT_INTERP`가 없는 완전한 static ELF로 덮어쓰며, 이 ELF의 코드는 `setuid(0)`을 호출한 뒤 `execve("/bin/sh", ...)`를 실행합니다. 따라서 원본 바이너리의 진입점, PIE 레이아웃, dynamic loader 또는 relocation에 관한 가정이 필요하지 않습니다.<sup>[[2]](#references)[[3]](#references)</sup>

page cache는 namespace로 분리되지 않으므로 변경 사항은 user namespace를 넘어 표시됩니다. 변경된 folio는 dirty로 표시되지 않아 디스크에 기록되지 않습니다. 대상 파일이 메모리에 있는 동안 실행한 다음 `posix_fadvise(..., POSIX_FADV_DONTNEED)`로 임시 변경 사항을 버리면, 이후 읽기에서 원래 디스크 콘텐츠를 다시 불러옵니다.<sup>[[2]](#references)[[3]](#references)</sup>

## Exposure checks and mitigation

먼저 실제 vendor kernel을 확인합니다. 관련 노출 조건은 unprivileged user namespace, OVS의 사용 가능 여부 또는 메모리 상주 여부, 그리고 ESP 구현의 사용 가능 여부입니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

완전한 수정 시리즈가 적용된 커널로 업그레이드하세요. 최종 수정은 recirculation 경로도 처리하고 공유된 `skb_shinfo()` 상태를 변경하지 않으며, `skb_zerocopy()`의 관련 strip 문제도 해결합니다.<sup>[[1]](#references)[[2]](#references)</sup>

OVS를 사용하지 않는다면 `blacklist`에만 의존하지 말고 modprobe `install` 규칙을 사용해 alias를 통한 로딩과 이름을 직접 지정한 로딩을 모두 차단하세요. 호스트에서 IPsec을 종료하지 않고 ESP가 모듈 방식으로 로드된다면, 같은 제어로 복호화 sink도 제거할 수 있습니다.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

이 규칙은 모듈이 이미 로드되었거나 기능이 커널에 내장된 경우에는 도움이 되지 않습니다. 권한 없는 user namespace를 비활성화하면 namespace 기능의 원천도 제거되지만, 브라우저, Flatpak, Podman 및 기타 sandbox/container 워크로드가 작동하지 않을 수 있습니다.<sup>[[2]](#references)</sup>

## 검토를 통해 얻은 교훈

zero-copy 네트워킹을 감사할 때 fragment를 복사하거나 이동하는 helper만 검색해서는 안 됩니다. 그룹화된 flag를 지우는 오류/완료 helper도 찾아낸 다음, 모든 호출자가 문서화된 skb 수명 계약을 준수하는지 확인해야 합니다. zerocopy 수명 주기 비트와 함께 그룹화된 페이지 소유권 비트는, 이를 지우는 코드가 fragment에 직접 접근하지 않더라도 보안에 민감합니다.<sup>[[1]](#references)[[2]](#references)</sup>

견고한 수정은 action continuation과 recirculation을 포함해 skb가 유지될 수 있는 모든 경로를 다뤄야 하며, clone이 `skb_shinfo()`를 공유하는 경우도 고려해야 합니다. consumer 측에서는 인증에 실패하더라도 in-place AEAD transform이 이미 수행한 plaintext 쓰기를 되돌리지 않습니다. 따라서 복호화를 시작하기 전에 외부 저장소 여부를 확인해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec netdev 수정 시리즈: net: forwarded skb에서 zerocopy frag marker를 제거하지 않도록 수정](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Open vSwitch Forwarded-SKB Marker Stripping을 통한 결정적 ESP Page-Cache LPE](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec `ovs-pagecache-write` proof of concept](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Fragnesia의 최초 coalescing 경로에 대한 Linux 수정 (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux ESP consumer 측 shared-fragment 검사 (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: IPsec ESP에서 Galois/Counter Mode (GCM) 사용](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Open vSwitch kernel datapath 문서](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
