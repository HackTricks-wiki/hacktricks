# 파일 무결성 모니터링

{{#include ../../banners/hacktricks-training.md}}

## 기준선

기준선은 시스템의 특정 부분을 스냅샷으로 저장하여 **향후 상태와 비교하고 변경 사항을 강조 표시**하는 것입니다.

예를 들어 파일시스템의 각 파일 해시를 계산하고 저장하면 어떤 파일이 수정되었는지 확인할 수 있습니다.\
이는 생성된 사용자 계정, 실행 중인 프로세스, 실행 중인 서비스 및 크게 또는 전혀 변경되어서는 안 되는 기타 항목에도 적용할 수 있습니다.

**유용한 기준선**은 일반적으로 digest만 저장하지 않습니다. 권한, 소유자, 그룹, 타임스탬프, inode, symlink 대상, ACL 및 선택한 extended attributes도 추적할 가치가 있습니다. 공격자 사냥 관점에서는 콘텐츠 해시가 가장 먼저 변경되지 않더라도 **권한만 변경하는 변조**, **atomic file replacement**, **수정된 service/unit 파일을 통한 persistence**를 탐지하는 데 도움이 됩니다.

### 파일 무결성 모니터링

File Integrity Monitoring (FIM)은 파일 변경 사항을 추적하여 IT 환경과 데이터를 보호하는 중요한 보안 기법입니다. 일반적으로 다음을 결합합니다.

1. **기준선 비교:** 향후 비교를 위해 메타데이터와 암호화 체크섬(`SHA-256` 또는 그 이상을 권장)을 저장합니다.
2. **실시간 알림:** OS-native 파일 이벤트를 구독하여 **어떤 파일이 언제 변경되었고, 가능하다면 어떤 프로세스/사용자가 해당 파일에 접근했는지** 확인합니다.
3. **주기적 재스캔:** 재부팅, 이벤트 유실, agent 중단 또는 의도적인 anti-forensic 활동 이후 신뢰도를 다시 확보합니다.

Threat hunting에서 FIM은 일반적으로 다음과 같은 **고가치 경로**에 집중할 때 더 유용합니다.

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## 실시간 Backend 및 Blind Spot

### Linux

수집 backend가 중요합니다:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: 쉽고 일반적이지만 watch limits가 소진될 수 있으며 일부 edge cases를 놓칩니다.
- **`auditd` / audit framework**: **누가 파일을 변경했는지**(`auid`, process, pid, executable)가 필요할 때 더 적합합니다.
- **`eBPF` / `kprobes`**: 최신 FIM stacks에서 event를 보강하고 일반적인 `inotify` deployments의 일부 operational 문제를 줄이는 데 사용되는 새로운 options입니다.

몇 가지 실무상 주의점:<sup>[[1]](#references)</sup>

- 프로그램이 `write temp -> rename` 방식으로 파일을 **교체**하면 파일 자체를 감시하는 것이 더 이상 유용하지 않을 수 있습니다. 파일만 감시하지 말고 **상위 디렉터리를 감시**하세요.
- `inotify` 기반 collectors는 **대규모 directory trees**, **hard-link activity**에서 또는 **감시 중인 파일이 삭제된 후** 이벤트를 놓치거나 성능이 저하될 수 있습니다.
- `fs.inotify.max_user_watches`, `max_user_instances` 또는 `max_queued_events`가 너무 낮으면 매우 큰 recursive watch sets가 조용히 실패할 수 있습니다.
- Network filesystems는 일반적으로 noise가 낮은 monitoring을 위한 FIM targets로 적합하지 않습니다.

AIDE를 사용한 기준선 + verification 예시:
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
프로세스 attribution이 필요하고 단순한 경로 수준의 변경만으로는 부족하다면, `osquery` `process_file_events` 또는 Wazuh `whodata` mode와 같은 audit 기반 telemetry를 우선 사용하세요.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Windows에서는 **change journals**를 **high-signal process/file telemetry**와 결합할 때 FIM의 효과가 더 강력해집니다:

- **NTFS USN Journal**은 파일 변경 사항을 volume별로 지속적으로 기록합니다.
- **Sysmon Event ID 11**은 파일 생성/overwrite를 탐지하는 데 유용합니다.
- **Sysmon Event ID 2**는 **timestomping** 탐지에 도움이 됩니다.
- **Sysmon Event ID 15**는 `Zone.Identifier` 또는 hidden payload streams와 같은 **named alternate data streams (ADS)**를 탐지하는 데 유용합니다.

간단한 USN triage 예시:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
더 깊이 있는 **timestamp manipulation**, **ADS abuse**, **USN tampering** 관련 anti-forensic 아이디어는 [Anti-Forensic Techniques](anti-forensic-techniques.md)를 확인하세요.

### Containers

Container FIM은 실제 write path를 자주 놓칩니다. Docker `overlay2`에서는 변경 사항이 read-only image layers가 아니라 Container의 **writable upper layer**(`upperdir`/`diff`)에 커밋됩니다. 따라서:

- 수명이 짧은 Container **내부**의 path만 모니터링하면 Container가 재생성된 후의 변경 사항을 놓칠 수 있습니다.
- writable layer를 뒷받침하는 **host path** 또는 관련 bind-mounted volume을 모니터링하는 것이 더 유용한 경우가 많습니다.
- image layers에 대한 FIM은 실행 중인 Container filesystem에 대한 FIM과 다릅니다.

## Attacker-Oriented Hunting Notes

- 바이너리만큼 **service definitions**와 **task schedulers**도 주의 깊게 추적하세요. Attackers는 `/bin/sshd`를 patch하는 대신 unit file, cron entry 또는 task XML을 수정하여 persistence를 확보하는 경우가 많습니다.
- content hash만으로는 충분하지 않습니다. 많은 compromise는 먼저 **owner/mode/xattr/ACL drift**로 나타납니다.
- 성숙한 intrusion이 의심된다면 두 가지를 모두 수행하세요: 새로운 activity를 확인하기 위한 **real-time FIM**과 신뢰할 수 있는 media에서 가져온 **cold baseline comparison**입니다.
- attacker가 root 또는 kernel execution 권한을 가지고 있다면 FIM agent, 해당 database, 심지어 event source까지 tamper될 수 있다고 가정하세요. 가능한 경우 logs와 baselines를 원격 또는 read-only media에 저장하세요.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osquery를 사용한 File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux 추적: File Integrity Monitoring 사용 사례 (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck 및 whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
