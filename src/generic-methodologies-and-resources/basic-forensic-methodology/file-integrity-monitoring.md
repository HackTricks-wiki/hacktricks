# 파일 무결성 모니터링

{{#include ../../banners/hacktricks-training.md}}

## 기준선

기준선은 시스템의 특정 부분을 스냅샷으로 저장하여 **향후 상태와 비교하고 변경 사항을 식별**하는 것입니다.

예를 들어 파일시스템의 각 파일 해시를 계산하고 저장하면 어떤 파일이 수정되었는지 확인할 수 있습니다.\
생성된 사용자 계정, 실행 중인 프로세스, 실행 중인 서비스 및 변경이 거의 또는 전혀 없어야 하는 기타 항목에도 동일한 작업을 수행할 수 있습니다.

**유용한 기준선**은 일반적으로 digest만 저장하지 않습니다. 권한, 소유자, 그룹, 타임스탬프, inode, symlink 대상, ACL 및 선택한 extended attributes도 추적할 가치가 있습니다.<sup>[[4]](#references)</sup> 공격자 hunting 관점에서 이는 콘텐츠 해시가 가장 먼저 변경되지 않더라도 **권한만 변조된 경우**, **atomic file replacement**, **수정된 service/unit 파일을 통한 persistence**를 탐지하는 데 도움이 됩니다.

### 파일 무결성 모니터링

File Integrity Monitoring (FIM)은 파일 변경 사항을 추적하여 IT 환경과 데이터를 보호하는 중요한 보안 기법입니다. 일반적으로 다음을 결합합니다:<sup>[[1]](#references)[[3]](#references)</sup>

1. **기준선 비교:** 향후 비교를 위해 메타데이터와 암호학적 체크섬(`SHA-256` 이상을 권장)을 저장합니다.
2. **실시간 알림:** OS-native 파일 이벤트를 구독하여 **어떤 파일이 언제 변경되었는지, 이상적으로는 어떤 프로세스/사용자가 해당 파일에 접근했는지** 확인합니다.
3. **주기적 재스캔:** reboot, 이벤트 유실, agent 중단 또는 의도적인 anti-forensic activity 이후 신뢰도를 다시 확보합니다.

Threat hunting에서 FIM은 일반적으로 다음과 같은 **high-value path**에 집중할 때 더 유용합니다.

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## 실시간 Backend 및 Blind Spot

### Linux

수집 backend가 중요합니다:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: 쉽고 일반적이지만 watch limit이 소진될 수 있으며 일부 edge case를 놓칩니다.
- **`auditd` / audit framework**: **누가 파일을 변경했는지**(login UID, process ID 및 process name) 확인해야 할 때 더 적합합니다.
- **`eBPF` / `kprobes`**: 최신 FIM stack에서 이벤트를 보강하고 일반적인 `inotify` deployment의 운영 부담을 일부 줄이기 위해 사용하는 newer option입니다.

몇 가지 실무상 주의점:<sup>[[1]](#references)[[5]](#references)</sup>

- 프로그램이 `write temp -> rename` 방식으로 파일을 **교체**하면 파일 자체를 감시하는 방식은 더 이상 유용하지 않을 수 있습니다. 파일만이 아니라 **parent directory를 감시**해야 합니다.
- `inotify` 기반 collector는 **매우 큰 directory tree**, **hard-link activity** 또는 **감시 중인 파일이 삭제된 이후** 이벤트를 놓치거나 성능이 저하될 수 있습니다.
- `fs.inotify.max_user_watches`, `max_user_instances` 또는 `max_queued_events`가 너무 낮으면 매우 큰 recursive watch set이 조용히 실패할 수 있습니다.
- `inotify` 기반 monitoring에서 network filesystem은 blind spot입니다. 원격 변경 사항이 보고되지 않기 때문입니다.

AIDE를 사용한 기준선 + verification 예시:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
공격자 persistence 경로에 초점을 맞춘 `osquery` FIM 구성 예시:<sup>[[1]](#references)</sup>
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
프로세스 귀속이 경로 수준의 변경만 필요한 것이 아니라면, `osquery`의 `process_file_events` 또는 Wazuh의 `whodata` mode와 같은 audit 기반 telemetry를 우선 사용하세요.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Windows에서는 **change journals**를 **high-signal process/file telemetry**와 결합할 때 FIM이 더욱 강력해집니다:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal**은 파일 변경 사항을 volume별로 지속적으로 기록합니다.
- **Sysmon Event ID 11**은 파일 생성/덮어쓰기를 탐지하는 데 유용합니다.
- **Sysmon Event ID 2**는 **timestomping** 탐지에 도움이 됩니다.
- **Sysmon Event ID 15**는 `Zone.Identifier` 또는 숨겨진 payload stream과 같은 **named alternate data streams (ADS)**에 유용합니다.

간단한 USN triage 예시:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
더 심층적인 **timestamp manipulation**, **ADS abuse**, **USN tampering** 관련 anti-forensic 아이디어는 [Anti-Forensic Techniques](anti-forensic-techniques.md)를 확인하세요.

### Containers

Container FIM은 실제 write path를 놓치는 경우가 많습니다. Docker `overlay2`에서는 container filesystem이 읽기 전용 image의 `lowerdir` layer와 쓰기 가능한 **upper layer** (`upperdir`/`diff`)를 결합하며, image 파일에 대한 write는 해당 upper layer로 copy up됩니다.<sup>[[8]](#references)</sup> 따라서:

- 수명이 짧은 container **내부**의 path만 모니터링하면 container가 재생성된 후의 변경 사항을 놓칠 수 있습니다.
- writable layer를 지원하는 **host path** 또는 관련 bind-mounted volume을 모니터링하는 것이 더 유용한 경우가 많습니다.
- image layer에 대한 FIM은 실행 중인 container filesystem에 대한 FIM과 다릅니다.

## Attacker-Oriented Hunting Notes

- binary만큼 **service definitions**와 **task schedulers**를 면밀히 추적하세요. Attackers는 `/bin/sshd`를 patch하기보다 unit file, cron entry 또는 task XML을 수정하여 persistence를 확보하는 경우가 많습니다.
- content hash만으로는 충분하지 않습니다. 많은 compromise는 먼저 **owner/mode/xattr/ACL drift**로 나타납니다.
- 성숙한 intrusion이 의심된다면 두 가지를 모두 수행하세요. 새로운 activity에는 **real-time FIM**을 사용하고, 신뢰할 수 있는 media에서 **cold baseline comparison**을 수행하세요.
- attacker가 root 또는 kernel execution 권한을 가지고 있다면 FIM agent와 해당 database를 신뢰할 수 없는 것으로 취급하세요. 가능한 경우 logs와 baselines를 원격 또는 read-only media에 저장하세요.<sup>[[4]](#references)</sup>

## Tools

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
{{#include ../../banners/hacktricks-training.md}}
