# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## 베이스라인

베이스라인은 시스템의 특정 부분을 스냅샷으로 찍어 향후 상태와 **비교하여 변경사항을 드러내는** 것입니다.

예를 들어, 파일 시스템의 각 파일에 대한 해시를 계산하여 저장하면 어떤 파일이 수정되었는지 알아낼 수 있습니다.\
이것은 생성된 사용자 계정, 실행 중인 프로세스, 실행 중인 서비스 및 거의 또는 전혀 변경되지 않아야 하는 기타 항목에도 적용할 수 있습니다.

유용한 베이스라인은 보통 단순한 다이제스트 이상을 저장합니다: 권한, 소유자, 그룹, 타임스탬프, inode, 심볼릭 링크 대상, ACLs 및 선택된 확장 속성 등을 추적할 가치가 있습니다. 공격자 헌팅 관점에서는, 이는 콘텐츠 해시가 가장 먼저 변경되는 것이 아닐 때에도 **permission-only tampering**, **atomic file replacement**, 및 **persistence via modified service/unit files**를 탐지하는 데 도움이 됩니다.

### File Integrity Monitoring

File Integrity Monitoring (FIM)은 파일의 변경을 추적하여 IT 환경과 데이터를 보호하는 중요한 보안 기법입니다. 일반적으로 다음을 결합합니다:

1. **Baseline comparison:** 미래 비교를 위해 메타데이터와 암호화 체크섬(가능하면 `SHA-256` 이상)을 저장합니다.
2. **Real-time notifications:** OS 네이티브 파일 이벤트를 구독하여 **어떤 파일이 언제 변경되었는지, 그리고 이상적으로는 어떤 프로세스/사용자가 변경했는지** 알 수 있게 합니다.
3. **Periodic re-scan:** 재부팅, 이벤트 누락, 에이전트 중단 또는 고의적인 반포렌식 활동 이후 신뢰를 재구축합니다.

위협 헌팅에서는 FIM이 보통 다음과 같은 **가치 높은 경로**에 집중할 때 더 유용합니다:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## 실시간 백엔드 및 사각지대

### Linux

수집 백엔드가 중요합니다:

- **`inotify` / `fsnotify`**: 쉽고 일반적이지만, 감시 한도가 소진될 수 있고 일부 엣지 케이스를 놓칩니다.
- **`auditd` / audit framework**: 누가 파일을 변경했는지(`auid`, process, pid, executable)가 필요할 때 더 낫습니다.
- **`eBPF` / `kprobes`**: 최신 FIM 스택에서 이벤트를 풍부하게 하고 단순 `inotify` 배포의 운영적 고통을 줄이기 위해 사용하는 최신 옵션들입니다.

몇 가지 실무상의 주의점:

- 프로그램이 `write temp -> rename` 방식으로 파일을 교체하면, 파일 자체를 감시하는 것은 더 이상 유용하지 않을 수 있습니다. 파일뿐만 아니라 **부모 디렉터리**를 감시하세요.
- `inotify` 기반 수집기는 **거대한 디렉터리 트리**, **하드링크 활동**, 또는 **감시 중인 파일이 삭제된 경우** 이벤트를 놓치거나 성능이 저하될 수 있습니다.
- 매우 큰 재귀적 감시 집합은 `fs.inotify.max_user_watches`, `max_user_instances`, 또는 `max_queued_events`가 너무 낮으면 아무런 경고 없이 실패할 수 있습니다.
- 네트워크 파일시스템은 보통 저잡음 모니터링에 적합하지 않습니다.

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
attacker persistence paths에 중점을 둔 `osquery` FIM 설정 예:
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
경로 수준 변경만으로는 부족하고 **프로세스 귀속**이 필요하다면, `osquery`의 `process_file_events`나 Wazuh의 `whodata` 모드와 같은 감사 기반 텔레메트리를 선호하세요.

### Windows

Windows에서는 FIM이 **변경 저널**과 **고신호 프로세스/파일 텔레메트리**를 결합할 때 더 강력합니다:

- **NTFS USN Journal**는 파일 변경에 대한 볼륨별 영구 로그를 제공합니다.
- **Sysmon Event ID 11**는 파일 생성/덮어쓰기에 유용합니다.
- **Sysmon Event ID 2**는 **timestomping** 감지에 도움이 됩니다.
- **Sysmon Event ID 15**는 `Zone.Identifier`나 숨겨진 payload 스트림과 같은 **named alternate data streams (ADS)**에 유용합니다.

빠른 USN 트리아지 예시:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
더 심도 있는 안티 포렌식 아이디어(예: **timestamp manipulation**, **ADS abuse**, **USN tampering**)는 [Anti-Forensic Techniques](anti-forensic-techniques.md)를 참고하세요.

### 컨테이너

Container FIM은 실제 쓰기 경로를 자주 놓칩니다. Docker `overlay2`에서는 변경사항이 읽기 전용 이미지 레이어가 아니라 컨테이너의 **쓰기 가능한 상위 레이어**(`upperdir`/`diff`)에 커밋됩니다. 따라서:

- 수명 짧은 컨테이너의 **내부** 경로만 모니터링하면 컨테이너가 재생성된 후의 변경을 놓칠 수 있습니다.
- 쓰기 가능한 레이어를 지원하거나 관련 바인드 마운트된 볼륨을 가리키는 **호스트 경로**를 모니터링하는 것이 종종 더 유용합니다.
- 이미지 레이어에 대한 FIM은 실행 중인 컨테이너 파일시스템에 대한 FIM과 다릅니다.

## 공격자 관점의 헌팅 노트

- 바이너리만큼 **서비스 정의**와 **작업 스케줄러**를 주의 깊게 추적하세요. 공격자는 종종 `/bin/sshd` 같은 바이너리를 패치하는 대신 유닛 파일, cron 항목, 또는 작업 XML을 수정하여 지속성을 얻습니다.
- 컨텐츠 해시만으로는 불충분합니다. 많은 침해는 처음에 **owner/mode/xattr/ACL drift**로 나타납니다.
- 성숙한 침입이 의심되는 경우, 둘 다 수행하세요: 새 활동을 위한 **real-time FIM**과 신뢰할 수 있는 매체에서의 **cold baseline comparison**.
- 공격자가 root 권한이나 커널 실행을 얻었다면 FIM 에이전트, 그 데이터베이스, 심지어 이벤트 소스까지 조작될 수 있다고 가정하세요. 가능한 경우 로그와 베이스라인을 원격지나 읽기 전용 매체에 저장하세요.

## 도구

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 참고 자료

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
