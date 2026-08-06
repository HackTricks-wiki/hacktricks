# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Baseline은 시스템의 특정 부분을 snapshot으로 저장하여 **향후 상태와 비교하고 변경 사항을 강조 표시**하는 것입니다.

예를 들어 파일시스템의 각 파일 hash를 계산하고 저장하면 어떤 파일이 수정되었는지 확인할 수 있습니다.\
이는 생성된 user account, 실행 중인 process, 실행 중인 service 및 변경이 거의 또는 전혀 없어야 하는 다른 모든 항목에도 적용할 수 있습니다.

**유용한 baseline**은 일반적으로 digest만 저장하지 않습니다. permissions, owner, group, timestamps, inode, symlink target, ACLs 및 선택된 extended attributes도 추적할 가치가 있습니다. Attacker hunting 관점에서 이는 content hash가 가장 먼저 변경되지 않더라도 **permission-only tampering**, **atomic file replacement**, **modified service/unit files를 통한 persistence**를 탐지하는 데 도움이 됩니다.

### File Integrity Monitoring

File Integrity Monitoring (FIM)은 파일의 변경 사항을 추적하여 IT 환경과 데이터를 보호하는 중요한 security technique입니다. 일반적으로 다음을 결합합니다:

1. **Baseline comparison:** 향후 비교를 위해 metadata와 cryptographic checksums (`SHA-256` 또는 그 이상을 선호)을 저장합니다.
2. **Real-time notifications:** OS-native file events를 subscribe하여 **어떤 파일이 언제 변경되었는지, 이상적으로는 어떤 process/user가 해당 파일에 접근했는지** 파악합니다.
3. **Periodic re-scan:** reboot, dropped events, agent outage 또는 의도적인 anti-forensic activity 이후 신뢰도를 다시 확보합니다.

Threat hunting에서는 일반적으로 다음과 같은 **high-value paths**에 집중할 때 FIM이 더 유용합니다:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers 및 bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

수집 backend가 중요합니다:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: 쉽고 일반적으로 사용되지만 watch limits가 소진될 수 있으며 일부 edge cases를 놓칩니다.
- **`auditd` / audit framework**: **누가 파일을 변경했는지**(`auid`, process, pid, executable)가 필요한 경우 더 적합합니다.
- **`eBPF` / `kprobes`**: 최신 FIM stacks에서 event를 보강하고 일반적인 `inotify` deployments의 운영상 문제를 일부 줄이는 데 사용되는 새로운 options입니다.

몇 가지 실용적인 주의 사항입니다:<sup>[[1]](#references)</sup>

- 프로그램이 `write temp -> rename` 방식으로 파일을 **replaces**하는 경우 파일 자체를 watching하는 것은 더 이상 유용하지 않을 수 있습니다. 파일만이 아니라 **parent directory를 watch**해야 합니다.
- `inotify`-based collectors는 **huge directory trees**, **hard-link activity** 또는 **watched file이 deleted된 이후** event를 놓치거나 성능이 저하될 수 있습니다.
- `fs.inotify.max_user_watches`, `max_user_instances` 또는 `max_queued_events`가 너무 낮으면 매우 큰 recursive watch sets가 조용히 실패할 수 있습니다.
- Network filesystems는 일반적으로 low-noise monitoring을 위한 FIM targets로 적합하지 않습니다.

AIDE를 사용한 baseline + verification 예시:
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
프로세스 단위 attribution이 필요하고 단순한 경로 수준 변경만으로는 부족하다면, `osquery` `process_file_events` 또는 Wazuh `whodata` mode와 같이 audit 기반 telemetry를 우선 사용하세요.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Windows에서는 **change journals**와 **high-signal process/file telemetry**를 함께 사용하면 FIM의 탐지 성능이 향상됩니다:

- **NTFS USN Journal**은 볼륨별 파일 변경 사항을 지속적으로 기록합니다.
- **Sysmon Event ID 11**은 파일 생성/덮어쓰기를 탐지하는 데 유용합니다.
- **Sysmon Event ID 2**는 **timestomping** 탐지에 도움이 됩니다.
- **Sysmon Event ID 15**는 `Zone.Identifier` 또는 숨겨진 payload stream과 같은 **named alternate data streams (ADS)**를 탐지하는 데 유용합니다.

간단한 USN triage 예시:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
더 심층적인 **timestamp manipulation**, **ADS abuse**, **USN tampering** 관련 anti-forensic 아이디어는 [Anti-Forensic Techniques](anti-forensic-techniques.md)를 확인하세요.

### 컨테이너

컨테이너 FIM은 실제 write path를 놓치는 경우가 많습니다. Docker `overlay2`에서는 변경 사항이 읽기 전용 image layers가 아니라 컨테이너의 **writable upper layer**(`upperdir`/`diff`)에 커밋됩니다. 따라서:

- 수명이 짧은 컨테이너 **내부**의 경로만 모니터링하면 컨테이너가 재생성된 후의 변경 사항을 놓칠 수 있습니다.
- writable layer를 지원하는 **호스트 경로** 또는 관련 bind-mounted volume을 모니터링하는 편이 더 유용한 경우가 많습니다.
- image layers에 대한 FIM은 실행 중인 컨테이너 filesystem에 대한 FIM과 다릅니다.

## Attacker-Oriented Hunting Notes

- 바이너리와 마찬가지로 **service definitions**와 **task schedulers**도 면밀히 추적하세요. Attackers는 `/bin/sshd`를 패치하기보다 unit file, cron entry 또는 task XML을 수정하여 persistence를 확보하는 경우가 많습니다.
- content hash만으로는 충분하지 않습니다. 많은 compromise는 먼저 **owner/mode/xattr/ACL drift**로 나타납니다.
- 성숙한 intrusion이 의심된다면 다음 두 가지를 모두 수행하세요: 새로운 activity를 확인하기 위한 **real-time FIM**과 trusted media를 사용한 **cold baseline comparison**.
- attacker가 root 또는 kernel execution 권한을 가지고 있다면 FIM agent, 해당 database, 심지어 event source까지 tamper될 수 있다고 가정하세요. 가능한 경우 logs와 baselines를 원격 또는 read-only media에 저장하세요.

## 도구

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 참고 자료

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
