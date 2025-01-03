# macOS 메모리 덤프

{{#include ../../../banners/hacktricks-training.md}}

## 메모리 아티팩트

### 스왑 파일

스왑 파일은 `/private/var/vm/swapfile0`와 같이 **물리적 메모리가 가득 찼을 때 캐시 역할을 합니다**. 물리적 메모리에 더 이상 공간이 없을 때, 그 데이터는 스왑 파일로 전송되고 필요에 따라 다시 물리적 메모리로 가져옵니다. 여러 개의 스왑 파일이 존재할 수 있으며, 이름은 swapfile0, swapfile1 등과 같습니다.

### 하이버네이트 이미지

`/private/var/vm/sleepimage`에 위치한 파일은 **하이버네이션 모드**에서 중요합니다. **OS X가 하이버네이트할 때 메모리의 데이터가 이 파일에 저장됩니다**. 컴퓨터가 깨어나면 시스템은 이 파일에서 메모리 데이터를 검색하여 사용자가 중단한 지점에서 계속할 수 있도록 합니다.

현대 MacOS 시스템에서는 이 파일이 보안상의 이유로 일반적으로 암호화되어 있어 복구가 어려운 점도 주목할 만합니다.

- sleepimage의 암호화가 활성화되어 있는지 확인하려면 `sysctl vm.swapusage` 명령을 실행할 수 있습니다. 이 명령은 파일이 암호화되어 있는지 보여줍니다.

### 메모리 압력 로그

MacOS 시스템에서 또 다른 중요한 메모리 관련 파일은 **메모리 압력 로그**입니다. 이 로그는 `/var/log`에 위치하며 시스템의 메모리 사용량 및 압력 이벤트에 대한 자세한 정보를 포함하고 있습니다. 메모리 관련 문제를 진단하거나 시스템이 시간이 지남에 따라 메모리를 관리하는 방식을 이해하는 데 특히 유용할 수 있습니다.

## osxpmem을 사용한 메모리 덤프

MacOS 기기에서 메모리를 덤프하려면 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)을 사용할 수 있습니다.

**참고**: 다음 지침은 Intel 아키텍처를 가진 Mac에서만 작동합니다. 이 도구는 현재 아카이브되었으며 마지막 릴리스는 2017년에 이루어졌습니다. 아래 지침을 사용하여 다운로드한 바이너리는 2017년에 Apple Silicon이 없었기 때문에 Intel 칩을 대상으로 합니다. arm64 아키텍처용으로 바이너리를 컴파일할 수 있을 수도 있지만, 직접 시도해 보아야 합니다.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
이 오류가 발생하면: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 다음과 같이 수정할 수 있습니다:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**다른 오류**는 "보안 및 개인 정보 보호 --> 일반"에서 **kext의 로드를 허용**하여 수정할 수 있습니다. 그냥 **허용**하세요.

이 **원라이너**를 사용하여 애플리케이션을 다운로드하고, kext를 로드하고, 메모리를 덤프할 수 있습니다:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
