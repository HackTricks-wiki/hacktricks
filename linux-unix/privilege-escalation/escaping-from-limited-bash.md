# Escaping from restricted shells - Jails

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io/) **if you can execute any binary with "Shell" property**

## Modify PATH

Check if you can modify the PATH env variable

```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```

## Create script

Check if you can create an executable file with _/bin/bash_ as content

```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```

## Get bash from SSH

If you are accessing via ssh you can use this trick to execute a bash shell:

```bash
ssh -t user@<IP> bash # Get directly an interactive shell
```

## Other tricks

\*\*\*\*[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)  
**\*\*\[**[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*\]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**]%28https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\)  
**\*\*\[**[https://gtfobins.github.io\*\*\]\(https://gtfobins.github.io](https://gtfobins.github.io**]%28https://gtfobins.github.io)\)  
**It could also be interesting the POST on** [**Bypass Bash restrictions**](../useful-linux-commands/bypass-bash-restrictions.md)\*\*\*\*

