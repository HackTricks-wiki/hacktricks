---
description: 'From http://hacking-printers.net/wiki/index.php/Factory_defaults'
---

# Factory Defaults

**Resetting** a device to factory defaults is a security-critical functionality as it **overwrites protection mechanisms** like user-set passwords. This can usually be done by pressing a **special key combination** on the printer's **control panel**. Performing such a cold reset only takes seconds and therefore is a realistic scenario for local attackers or penetration testers, who can for example sneak into the copy room at lunchtime. However, **physical access** to the device is **not always an option**.

#### SNMP

The Printer-MIB defines the **prtGeneralReset** Object \(**OID 1.3.6.1.2.1.43.5.1.1.3.1**\) which allows an attacker to restart the device \(powerCycleReset\(4\)\), reset the NVRAM settings \(resetToNVRAM\(5\)\) or restore factory defaults \(resetToFactoryDefaults\(6\)\) using SNMP. This feature/attack is **supported by a large variety of printers** and removes all protection mechanisms like user-set passwords for the embedded web server. While protection mechanisms can be efficiently bypassed, a practical drawback of this approach is that all **static IP address configuration will be lost**. **If no DHCP** service is available, the attacker will **not** be able to **reconnect** to the device anymore after resetting it to factory defaults.

**Resetting the device to factory default** can be accomplished using `snmpset` command as shown below \(you need to know the **community string**, by default in most cases is `public`\):

```bash
snmpset -v1 -c public printer 1.3.6.1.2.1.43.5.1.1.3.1 i 6
```

#### [PML](./#pml)/[PJL](./#pjl)

In many scenarios an attacker does not have the capabilities to perform SNMP requests because of firewalls or unknown SNMP community strings. On **HP devices** however, **SNMP** can be transformed into its **PML representation** and embed the request within a legitimate print job. This allows an attacker to **restart and/or reset the device** to factory defaults within ordinary print jobs as shown below:

```bash
@PJL DMCMD ASCIIHEX="040006020501010301040106"
```

Anyone can reproduce this attack on HP printers, restarting or resetting the device can easily be reproduced using [**PRET**](https://github.com/RUB-NDS/PRET):

```bash
./pret.py -q printer pjl
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> reset
printer:/> restart
```

#### PostScript

PostScript offers a similar feature: The **FactoryDefaults** system parameter, ‘a flag that, if **set to true** **immediately before** the **printer is turned off**, causes all nonvolatile parameters to revert to their **factory default** values at the next power-on’. It must be noted that **PostScript** itself also has the capability to **restart** its **environment** but it requires a **valid password**.   
The PostScript interpreter however can be put into an **infinite loop** as discussed in [document processing](http://hacking-printers.net/wiki/index.php/Document_processing) DoS attacks which forces the user to **manually restart** the device and thus reset the PostScript password.

Reset PostScript system parameters to factory defaults:

```bash
<< /FactoryDefaults true >> setsystemparams
```

Restart the PostScript interpreter and virtual memory:

```bash
true 0 startjob systemdict /quit get exec
```

Anyone can restart or reset a printer's PostScript interpreter can **easily be reproduced using** [**PRET**](https://github.com/RUB-NDS/PRET):

```bash
./pret.py -q printer ps
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> reset
printer:/> restart
```

#### PRESCRIBE

For **Kyocera devices**, the **PRESCRIBE page** description languages may be used to **reset the device** to factory default from within ordinary print jobs using one of the commands shown below:

```bash
!R! KSUS "AUIO", "CUSTOM:Admin Password = 'admin00'";  CMMT "Drop the security level, reset password";
!R! ACNT "REST";                                       CMMT "Reset account code admin password";
!R! EGRE;                                              CMMT "Reset the engine board to factory defaults";
!R! SIOP0,"RESET:0";                                   CMMT "Reset configuration settings";
```

To reproduce this attack open a raw network connection to port 9100/tcp of the printer and **send the commands documented above**.

