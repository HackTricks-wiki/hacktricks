# 네트워크 정보

{{#include ../../banners/hacktricks-training.md}}

로컬 리스너, Unix 소켓, 네트워크에 노출된 소프트웨어는 외부 스캔으로는 보이지 않는 경로를 드러낼 수 있습니다. 호스트의 리스닝 서비스와 각 엔드포인트를 소유한 프로세스부터 확인하세요.

- [트래픽 캡처, 방화벽 및 송신 트래픽 분류](traffic-capture-and-firewall-egress.md)에서는 패킷 캡처, 필터링, 프록시, 연결 테스트를 다룹니다.
- [로컬 네트워크 및 소켓 분류](local-network-and-socket-triage.md)에서는 루프백 서비스, Unix 소켓, 컨테이너 네트워크를 다룹니다.
- [Socket command injection](socket-command-injection.md)에서는 노출된 로컬 소켓을 통해 전달되는 명령을 다룹니다.
- Cisco SD-WAN Manager 어플라이언스에 foothold를 확보하려면 [vManage local privilege escalation](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md)을 참조하세요. 해당 문서의 ConfD CLI, REST API, root 소유 가져오기 경로는 일반적인 소켓 분류와는 별개입니다.
{{#include ../../banners/hacktricks-training.md}}
