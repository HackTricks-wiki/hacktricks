# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## 범위

침해 후 implant는 서명된 kernel driver를 service로 로드하고 `IRP_MJ_DEVICE_CONTROL`을 통해 user-mode control plane을 노출할 수 있습니다. Driver signing은 Windows가 해당 image를 허용한다는 것만 입증할 뿐이며, IOCTL authorization, memory operations, callbacks 또는 hooks가 안전하다는 의미는 아닙니다. 분석된 한 rootkit은 정상 작동 중 세 개의 handler를 사용했지만 수십 개의 추가 post-exploitation primitive를 노출했으므로, reverse engineering은 malware trace에서 관찰된 request뿐만 아니라 전체 dispatcher를 다뤄야 합니다.<sup>[[1]](#references)</sup>

## Signed-driver 및 IOCTL triage

`DriverEntry`에서 시작하여 device objects와 DOS symbolic links를 기록하고, `MajorFunction[IRP_MJ_DEVICE_CONTROL]` routine을 찾은 다음 handler에 도달하는 모든 comparison/table entry를 매핑합니다. user mode에서 여는 이름과 driver가 실제로 생성하는 이름을 대조합니다. 관찰된 한 chain은 `\\.\msagent`를 연 반면, 해당 driver는 `\Device\ToolTool` 및 `\DosDevices\ToolTool`을 생성했습니다. 이러한 불일치는 다른 sample/configuration, 누락된 setup logic 또는 분석 불일치를 식별하는 데 도움이 될 수 있습니다.<sup>[[1]](#references)</sup>

각 control code를 해석한 후 input structure를 재구성합니다.<sup>[[1]](#references)</sup>
```python
def decode_ioctl(code):
return {
"device_type": code >> 16,
"access": (code >> 14) & 3,
"function": (code >> 2) & 0xfff,
"method": code & 3,
}

for code in (0x2220F0, 0x222120, 0x2221E0):
print(hex(code), decode_ioctl(code))
```
이 세 코드는 각각 `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS`, `METHOD_BUFFERED`로 decode됩니다. 그렇다고 해서 권한이 없는 caller가 해당 코드에 접근할 수 있다는 의미는 아닙니다. device DACL, create/open dispatch, 요청별 caller 검사, 예상되는 buffer 길이, embedded pointer, PID lifetime 처리, 그리고 handler가 caller가 제공한 PID 또는 flag를 신뢰하는지도 함께 확인해야 합니다.<sup>[[1]](#references)</sup>

implant가 일부 command만 사용하는 경우, 나머지 handler를 dead code로 치부하지 말고 primitive별로 그룹화하십시오. 하나의 multifunction driver가 다음 모든 class를 노출한 사례가 있습니다.<sup>[[1]](#references)</sup>

- **Control/configuration:** rootkit 상태를 전환하고, 보호된 path, process, C2 address를 추가, 제거, 조회 또는 초기화합니다.
- **Process manipulation:** PID를 종료하고, 해당 image를 unmap하며, `NtCreateThreadEx`로 inject하고, process 또는 user module을 hide/restore하며, PPL protection을 제거합니다.
- **Kernel manipulation:** loaded driver를 unlink하고, notification callback을 열거/비활성화/복원하며, 다른 driver를 manually map하고, 임의의 kernel address에 write합니다.
- **Object manipulation:** file을 delete/decrypt하고 registry value를 생성하거나 수정합니다.

## Trusted-process exemptions

유용한 design pattern은 PID와 **trusted** flag를 등록하는 IOCTL입니다. 동일한 trust lookup은 file, registry, process, thread filter에서 사용됩니다. untrusted tool에는 필터링된 enumeration 결과, 축소된 handle 권한 또는 `STATUS_ACCESS_DENIED`가 전달되는 반면, implant는 자체 hidden object를 계속 업데이트할 수 있습니다. 이를 authorization boundary로 간주하고, process 종료 또는 PID reuse 이후 entry가 어떻게 authenticate, synchronize, remove되는지 확인하십시오.<sup>[[1]](#references)</sup>

Rootkit은 `REG_MULTI_SZ` value에 policy를 저장하고 file, directory, registry-key, registry-value, ignored-image, protected-image, hidden-image list를 AVL tree로 compile할 수 있습니다. 분석 중에는 이러한 shared tree의 모든 reader와 writer를 추적하십시오. 이를 통해 function name이 stripped된 경우에도 registry configuration, IOCTL, callback, filtering logic을 연결할 수 있습니다.<sup>[[1]](#references)</sup>

## DKOM process and module hiding

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` offset은 Windows build마다 다릅니다. version-tolerant rootkit은 알려진 candidate를 테스트한 다음 `EPROCESS`를 scan하여 neighbor가 candidate를 다시 가리키는 self-consistent `LIST_ENTRY`를 찾을 수 있습니다. 발견한 offset을 유지하고, process를 hide할 때 neighbor의 `Flink`/`Blink`를 reconnect하며, 나중에 entry를 relink할 수 있도록 상태를 보존합니다. process는 계속 실행되지만 active-process list를 순회하는 enumerator에서는 사라집니다.<sup>[[1]](#references)</sup>

이는 termination이 아니라 **DKOM**입니다. Detection에서는 list 기반 결과를 pool/object scan, thread ownership, handle table, scheduler artifact, kernel memory inspection과 같은 독립적인 evidence와 비교해야 합니다. scan에는 보이지만 canonical list에는 없는 process가 어느 한쪽 view만 사용하는 것보다 더 의미 있는 결과입니다.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

동등한 module-hiding primitive는 `PsLoadedModuleList`에서 target entry를 찾고 인접한 `Flink`/`Blink` pointer를 patch합니다. driver는 여전히 mapped 및 executable 상태이지만 list 기반 module query에서는 제외됩니다. loader list를 executable kernel mapping, pool tag, device/driver object, service key, callback address, 그리고 listed image 외부를 가리키는 dispatch pointer와 비교하십시오.<sup>[[1]](#references)</sup>

## Callback-based protection and cloaking

Rootkit은 documented callback framework를 DKOM 및 hook과 결합할 수 있습니다.<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` pre-operation handler는 `PsProcessType` 및 `PsThreadType`에 대해 동작하며, untrusted caller가 protected target을 open할 때 termination, VM access, duplication 또는 thread manipulation에 사용되는 권한을 제거합니다. callback altitude를 기록하고 각 callback address를 해당 owner module로 resolve하십시오.
- `PsSetCreateProcessNotifyRoutineEx` 및 `PsSetLoadImageNotifyRoutine`은 process와 image가 나타날 때 protected/ignored/hidden process 상태를 유지합니다. one-time process walk를 통해 registration 전에 존재했던 object를 backfill할 수 있습니다.
- filesystem minifilter는 configured path에 대한 access를 deny합니다. 비정상적인 구현은 `Instances` key를 생성하고, altitude를 동적으로 선택하며, `FltRegisterFilter`가 collision을 보고하면 값을 increment하고 retry할 수 있습니다.
- `CmRegisterCallbackEx` routine은 enumeration에서 protected name을 suppress하고 direct open, rename, set 또는 delete operation을 deny하면서 등록된 trusted process는 exempt할 수 있습니다.

`ObRegisterCallbacks` registration, registry-callback altitude, `fltmc filters` output, service `Instances` key, callback address를 correlate하십시오. 일반적인 tool이 filtering되고 있다면 offline memory image 또는 다른 trusted acquisition layer에서 이러한 structure를 inspect하십시오.<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Network concealment는 `\Driver\Nsiproxy`를 대상으로 할 수 있습니다. `ObReferenceObjectByName`으로 driver object를 얻고, handler pointer를 저장한 뒤, 이를 wrapper로 교체하며, user mode가 수신하기 전에 IOCTL로 관리되는 C2 list와 일치하는 반환 IPv4 record를 제거합니다. 필터링된 NSI data를 기반으로 하는 application은 traffic이 여전히 존재하더라도 해당 connection을 더 이상 표시하지 않을 수 있습니다.<sup>[[1]](#references)</sup>

Host connection view를 packet capture, WFP/ETW telemetry 및 kernel-memory network object와 비교하십시오. 또한 `Nsiproxy` dispatch/handler pointer를 inspect하고 각각이 예상되는 signed module 내부로 resolve되는지 확인하십시오. listed mapping 외부를 가리키는 pointer는 network filtering을 `PsLoadedModuleList` DKOM과 연결할 수 있습니다.<sup>[[1]](#references)</sup>

## Investigation checklist

가장 강력한 signal은 하나의 filename이나 hash가 아니라 layer 간의 불일치입니다. 다음 항목을 correlate하십시오.<sup>[[1]](#references)</sup>

1. Kernel-service creation과 certificate age, publisher 또는 path가 installed product와 일치하지 않는 signed driver.
2. Device creation, DOS link 및 IOCTL traffic, 특히 user-mode와 kernel device name이 서로 일치하지 않는 경우.
3. PID registration request 이후 다른 process가 동일한 object를 open, enumerate, modify 또는 delete하지 못하는 현상.
4. 일반적으로 열거되는 driver에 속하지 않는 address를 가진 object/registry/process/image callback, minifilter instance 및 hook.
5. List 기반 및 scan 기반 process, module, callback, network inventory 간의 차이.

## References

- [1] [Kaspersky Securelist - Signed Windows Kernel Rootkit으로 CoolClient를 강화한 HoneyMyte](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
