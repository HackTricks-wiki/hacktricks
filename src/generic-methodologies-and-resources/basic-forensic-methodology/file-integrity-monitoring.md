# 파일 무결성 모니터링

{{#include ../../banners/hacktricks-training.md}}

## 기준선

기준선은 시스템의 특정 부분을 스냅샷으로 저장하여 **향후 상태와 비교하고 변경 사항을 확인**하는 것입니다.

예를 들어 파일시스템의 각 파일에 대한 해시를 계산하고 저장하면 어떤 파일이 수정되었는지 확인할 수 있습니다.\
생성된 사용자 계정, 실행 중인 프로세스, 실행 중인 서비스 및 변경이 거의 또는 전혀 없어야 하는 다른 모든 항목에도 이 방법을 적용할 수 있습니다.

**유용한 기준선**은 일반적으로 digest만 저장하지 않습니다. 권한, 소유자, 그룹, 타임스탬프, inode, 심볼릭 링크 대상, ACL 및 선택된 확장 속성도 추적할 가치가 있습니다.<sup>[[4]](#references)</sup> 공격자 헌팅 관점에서는 콘텐츠 해시가 가장 먼저 변경되지 않더라도 **권한만 변경하는 변조**, **atomic file replacement**, **수정된 service/unit 파일을 통한 persistence**를 탐지하는 데 도움이 됩니다.

### File Integrity Monitoring

File Integrity Monitoring (FIM)은 파일의 변경 사항을 추적하여 IT 환경과 데이터를 보호하는 중요한 보안 기법입니다. 일반적으로 다음을 결합합니다:<sup>[[1]](#references)[[3]](#references)</sup>

1. **기준선 비교:** 향후 비교를 위해 메타데이터와 암호화 체크섬(`SHA-256` 이상을 권장)을 저장합니다.
2. **실시간 알림:** OS-native 파일 이벤트를 구독하여 **어떤 파일이 언제 변경되었고, 가능하면 어떤 프로세스/사용자가 해당 파일에 접근했는지** 확인합니다.
3. **주기적 재스캔:** 재부팅, 이벤트 유실, agent 중단 또는 의도적인 anti-forensic 활동 이후 신뢰도를 다시 확보합니다.

Threat hunting에서는 다음과 같은 **high-value path**에 집중할 때 FIM이 일반적으로 더 유용합니다.

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron 위치, SSH material, PAM modules, web roots
- Windows persistence 위치, service binaries, scheduled task files, startup folders
- Container writable layers 및 bind-mounted secrets/configuration

## 실시간 Backend 및 Blind Spot

### Linux

수집 backend가 중요합니다:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: 쉽고 일반적으로 사용되지만 watch limit이 소진될 수 있으며 일부 edge case를 놓칩니다.
- **`auditd` / audit framework**: **누가 파일을 변경했는지**(login UID, process ID 및 process name) 확인해야 할 때 더 적합합니다.
- **`eBPF` / `kprobes`**: 최신 FIM stack에서 이벤트 정보를 보강하고 일반적인 `inotify` deployment의 운영상 문제를 일부 줄이는 데 사용하는 새로운 옵션입니다.

실무에서 주의할 사항은 다음과 같습니다:<sup>[[1]](#references)[[5]](#references)</sup>

- 프로그램이 `write temp -> rename` 방식으로 파일을 **교체**하는 경우 파일 자체를 감시하는 것은 더 이상 유용하지 않을 수 있습니다. 파일만 감시하지 말고 **상위 directory를 감시**해야 합니다.
- `inotify` 기반 collector는 **매우 큰 directory tree**, **hard-link activity** 또는 **감시 중인 파일이 삭제된 이후** 이벤트를 놓치거나 성능이 저하될 수 있습니다.
- 재귀 watch set이 매우 큰 경우 `fs.inotify.max_user_watches`, `max_user_instances` 또는 `max_queued_events` 값이 너무 낮으면 오류가 표시되지 않은 채 실패할 수 있습니다.
- `inotify` 기반 monitoring에서 network filesystem은 blind spot입니다. 원격 변경 사항은 보고되지 않기 때문입니다.

AIDE를 사용한 기준선 설정 및 검증 예시:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
공격자의 persistence 경로에 초점을 맞춘 `osquery` FIM 구성 예시:<sup>[[1]](#references)</sup>
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
프로세스 attribution이 필요하고 단순히 경로 수준의 변경만으로는 충분하지 않다면, `osquery` `process_file_events` 또는 Wazuh `whodata` mode와 같이 audit 기반 telemetry를 우선 사용하세요.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: syscall telemetry는 FIM이 아님

최신 Linux에서는 `openat(2)`, `write(2)` 또는 기타 syscall 진입점을 감시하는 것이 **그 결과로 발생한 filesystem operation을 모니터링하는 것과 동등하지 않습니다**. 2025년 **Curing** proof of concept는 `io_uring`을 통해 file 및 network request를 큐에 추가했으므로, 해당 per-operation syscall entry에만 연결된 제품이나 policy는 process telemetry를 놓쳤습니다. 동일한 테스트에서 path-scoped FIM component는 여전히 file modification을 관찰했으며, 이는 permission bypass나 모든 FIM backend를 무력화하는 방법이 아니라 **hook 배치의 사각지대**임을 보여줍니다.<sup>[[10]](#references)</sup>

Sensor를 검증할 때는 여러 경로를 통해 동일한 canary를 수정하세요: 일반 `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomic replacement 및 `io_uring`. 최종 hash drift가 감지되는지만 확인하지 말고, event가 responsible process, container/cgroup, namespace-visible path, inode 및 rename pair를 보존하는지도 확인하세요. 실시간 event가 누락된 후 periodic scan mismatch가 발생했다면 이를 **telemetry loss**로 처리해야 하며, 일상적인 원인 불명의 변경으로 처리해서는 안 됩니다.<sup>[[10]](#references)[[11]](#references)</sup>

eBPF 기반 monitoring에서는 syscall-entry probe 목록보다 일반적인 kernel enforcement point를 우선 사용하세요. 예를 들어 Tetragon의 file-access policy는 `security_file_permission`을 사용하여 일반적인 I/O, `sendfile`, `copy_file_range`, AIO 및 `io_uring`을 포괄하며, memory mapping은 `security_mmap_file`, size change는 `security_path_truncate`로 별도로 처리합니다. 이는 하나의 hook만으로는 완전한 coverage를 제공하기 어려운 이유도 보여줍니다.<sup>[[11]](#references)</sup>

### Windows

Windows에서는 **change journal**과 **high-signal process/file telemetry**를 결합할 때 FIM이 더 강력해집니다:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal**은 volume별 file change에 대한 영구 log를 제공합니다.
- **Sysmon Event ID 11**은 file creation/overwrite에 유용합니다.
- **Sysmon Event ID 2**는 **timestomping** 감지에 도움이 됩니다.
- **Sysmon Event ID 15**는 `Zone.Identifier` 또는 hidden payload stream과 같은 **named alternate data stream (ADS)**에 유용합니다.

빠른 USN triage 예시:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
더 깊이 있는 **timestamp manipulation**, **ADS abuse**, **USN tampering** 관련 anti-forensic 아이디어는 [Anti-Forensic Techniques](anti-forensic-techniques.md)를 참고하세요.

### Containers

Container FIM은 실제 쓰기 경로를 자주 놓칩니다. Docker `overlay2`에서는 컨테이너 파일시스템이 읽기 전용 이미지 `lowerdir` 계층과 쓰기 가능한 **upper layer** (`upperdir`/`diff`)를 결합하며, 이미지 파일에 대한 쓰기는 해당 upper layer로 copy up됩니다.<sup>[[8]](#references)</sup> 따라서:

- 짧은 수명의 컨테이너 **내부** 경로만 모니터링하면 컨테이너가 재생성된 후의 변경 사항을 놓칠 수 있습니다.
- 쓰기 가능한 계층을 지원하는 **호스트 경로** 또는 관련 bind-mounted volume을 모니터링하는 것이 더 유용한 경우가 많습니다.
- 이미지 계층에 대한 FIM은 실행 중인 컨테이너 파일시스템에 대한 FIM과 다릅니다.

## 공격자 관점의 헌팅 참고 사항

- 바이너리만큼 **service definitions**와 **task schedulers**를 주의 깊게 추적하세요. 공격자는 `/bin/sshd`를 패치하기보다 unit file, cron entry 또는 task XML을 수정해 persistence를 확보하는 경우가 많습니다.
- content hash만으로는 충분하지 않습니다. 많은 compromise는 먼저 **owner/mode/xattr/ACL drift**로 나타납니다.
- 성숙한 intrusion이 의심된다면 두 가지를 모두 수행하세요. 새로운 activity에 대해서는 **real-time FIM**을 사용하고, 신뢰할 수 있는 media에서 **cold baseline comparison**을 수행합니다.
- 공격자가 root 또는 kernel execution 권한을 가지고 있다면 FIM agent와 해당 database를 신뢰할 수 없는 것으로 간주하세요. 가능한 경우 logs와 baselines를 원격 또는 read-only media에 저장하세요.<sup>[[4]](#references)</sup>

## 도구

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osquery를 사용한 File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux 추적: File Integrity Monitoring 사용 사례 (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck 및 whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE Manual Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux manual page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit Bypasses Linux Security Tools (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Filename access: covering synchronous, asynchronous, mapped, and truncation paths (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
