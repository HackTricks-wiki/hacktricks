# 리눅스 환경 변수

{{#include ../banners/hacktricks-training.md}}

## 전역 변수

전역 변수는 **자식 프로세스**에 의해 **상속됩니다**.

현재 세션을 위한 전역 변수를 생성하려면:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
이 변수는 현재 세션과 그 자식 프로세스에서 접근할 수 있습니다.

변수를 **제거**하려면 다음을 수행하십시오:
```bash
unset MYGLOBAL
```
## 로컬 변수

**로컬 변수**는 **현재 셸/스크립트**에서만 **접근**할 수 있습니다.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 현재 변수 목록
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X**에서 사용하는 디스플레이. 이 변수는 보통 **:0.0**으로 설정되며, 이는 현재 컴퓨터의 첫 번째 디스플레이를 의미합니다.
- **EDITOR** – 사용자가 선호하는 텍스트 편집기.
- **HISTFILESIZE** – 히스토리 파일에 포함된 최대 라인 수.
- **HISTSIZE** – 사용자가 세션을 종료할 때 히스토리 파일에 추가되는 라인 수.
- **HOME** – 홈 디렉토리.
- **HOSTNAME** – 컴퓨터의 호스트 이름.
- **LANG** – 현재 언어.
- **MAIL** – 사용자의 메일 스풀 위치. 보통 **/var/spool/mail/USER**.
- **MANPATH** – 매뉴얼 페이지를 검색할 디렉토리 목록.
- **OSTYPE** – 운영 체제의 유형.
- **PS1** – bash의 기본 프롬프트.
- **PATH** – 파일 이름만 지정하여 실행하고자 하는 바이너리 파일이 있는 모든 디렉토리의 경로를 저장합니다.
- **PWD** – 현재 작업 디렉토리.
- **SHELL** – 현재 명령 셸의 경로 (예: **/bin/bash**).
- **TERM** – 현재 터미널 유형 (예: **xterm**).
- **TZ** – 시간대.
- **USER** – 현재 사용자 이름.

## Interesting variables for hacking

### **HISTFILESIZE**

이 변수의 **값을 0으로 변경**하면, **세션을 종료할 때** **히스토리 파일** (\~/.bash_history) **이 삭제됩니다**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

이 **변수의 값을 0으로 변경**하면, **세션을 종료할 때** 어떤 명령도 **히스토리 파일** (\~/.bash_history)에 추가되지 않습니다.
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

프로세스는 **http 또는 https**를 통해 인터넷에 연결하기 위해 여기에서 선언된 **프록시**를 사용할 것입니다.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

프로세스는 **이 환경 변수**에 표시된 인증서를 신뢰합니다.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

프롬프트 모양을 변경합니다.

[**이것은 예시입니다**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

루트:

![](<../images/image (897).png>)

일반 사용자:

![](<../images/image (740).png>)

하나, 둘, 셋의 백그라운드 작업:

![](<../images/image (145).png>)

하나의 백그라운드 작업, 하나의 중지된 작업 및 마지막 명령이 올바르게 완료되지 않음:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
