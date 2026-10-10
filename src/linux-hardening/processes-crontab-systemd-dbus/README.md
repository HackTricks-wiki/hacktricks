# 프로세스, Crontab, Systemd 및 D-Bus

{{#include ../../banners/hacktricks-training.md}}

예약된 작업과 프로세스 간 통신은 호출자와 다른 권한으로 코드를 실행할 수 있습니다. 테스트하기 전에 서비스나 작업의 소유자, 명령 및 쓰기 가능한 입력을 확인하세요.

- [프로세스 열거 및 서비스 경로](process-enumeration-and-service-paths.md)는 프로세스 트리, 런타임 파일 및 systemd 실행 체인을 다룹니다.
- [Cron 작업 및 systemd 타이머](cron-and-systemd-timers.md)는 예약된 작업을 찾고 쓰기 가능한 입력을 확인하는 방법을 다룹니다.
- [D-Bus 열거 및 명령어 삽입을 통한 권한 상승](d-bus-enumeration-and-command-injection-privilege-escalation.md)은 메시지 버스와 권한이 있는 서비스 메서드를 다룹니다.
- [실행할 Payload](payloads-to-execute.md)에는 실행 경로를 식별했을 때 사용할 수 있는 Payload가 모여 있습니다.

Cron 작업과 systemd 서비스 전반을 검토하려면 [Linux 권한 상승 체크리스트](../main-system-information/linux-privilege-escalation-checklist.md)를 참고하세요.
{{#include ../../banners/hacktricks-training.md}}
