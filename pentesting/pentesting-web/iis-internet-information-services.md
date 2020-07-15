# IIS - Internet Information Services

Test executable file extensions:

* asp
* aspx
* config
* php

## Internal IP Address disclosure

On any IIS server where you get a 302 you can try stripping the Host header and using HTTP/1.0 and inside the response the Location header could point you to the internal IP address:

```text
nc -v domain.com 80
openssl s_client -connect domain.com:443
```

Response disclosing the internal IP:

```text
GET / HTTP/1.0       

HTTP/1.1 302 Moved Temporarily
Cache-Control: no-cache
Pragma: no-cache
Location: https://192.168.5.237/owa/
Server: Microsoft-IIS/10.0
X-FEServer: NHEXCHANGE2016

```

## Execute .config files

You can upload .config files and use them to execute code. One way to do it is appending the code at the end of the file inside an HTML comment: [Download example here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20insecure%20files/Configuration%20IIS%20web.config/web.config)

More information and techniques to exploit this vulnerability [here](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)

## IIS HTTP Bruteforce

Download the list that I have created: 

{% file src="../../.gitbook/assets/iisfinal.txt" %}

It was created merging the contents of the following lists:

[https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt)  
[http://itdrafts.blogspot.com/2013/02/aspnetclient-folder-enumeration-and.html](http://itdrafts.blogspot.com/2013/02/aspnetclient-folder-enumeration-and.html)  
[https://github.com/digination/dirbuster-ng/blob/master/wordlists/vulns/iis.txt](https://github.com/digination/dirbuster-ng/blob/master/wordlists/vulns/iis.txt)  
[https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SVNDigger/cat/Language/aspx.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SVNDigger/cat/Language/aspx.txt)  
[https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SVNDigger/cat/Language/asp.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SVNDigger/cat/Language/asp.txt)  
[https://raw.githubusercontent.com/xmendez/wfuzz/master/wordlist/vulns/iis.txt](https://raw.githubusercontent.com/xmendez/wfuzz/master/wordlist/vulns/iis.txt)

Use it without adding any extension, the files that need it have it already.

## Local File Inclusion list

From [here](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)

```text
C:\Apache\conf\httpd.conf
C:\Apache\logs\access.log
C:\Apache\logs\error.log
C:\Apache2\conf\httpd.conf
C:\Apache2\logs\access.log
C:\Apache2\logs\error.log
C:\Apache22\conf\httpd.conf
C:\Apache22\logs\access.log
C:\Apache22\logs\error.log
C:\Apache24\conf\httpd.conf
C:\Apache24\logs\access.log
C:\Apache24\logs\error.log
C:\Documents and Settings\Administrator\NTUser.dat
C:\php\php.ini
C:\php4\php.ini
C:\php5\php.ini
C:\php7\php.ini
C:\Program Files (x86)\Apache Group\Apache\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache\logs\access.log
C:\Program Files (x86)\Apache Group\Apache\logs\error.log
C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache2\logs\access.log
C:\Program Files (x86)\Apache Group\Apache2\logs\error.log
c:\Program Files (x86)\php\php.ini"
C:\Program Files\Apache Group\Apache\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\logs\access.log
C:\Program Files\Apache Group\Apache\conf\logs\error.log
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
C:\Program Files\Apache Group\Apache2\conf\logs\access.log
C:\Program Files\Apache Group\Apache2\conf\logs\error.log
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Program Files\MySQL\my.cnf
C:\Program Files\MySQL\my.ini
C:\Program Files\MySQL\MySQL Server 5.0\my.cnf
C:\Program Files\MySQL\MySQL Server 5.0\my.ini
C:\Program Files\MySQL\MySQL Server 5.1\my.cnf
C:\Program Files\MySQL\MySQL Server 5.1\my.ini
C:\Program Files\MySQL\MySQL Server 5.5\my.cnf
C:\Program Files\MySQL\MySQL Server 5.5\my.ini
C:\Program Files\MySQL\MySQL Server 5.6\my.cnf
C:\Program Files\MySQL\MySQL Server 5.6\my.ini
C:\Program Files\MySQL\MySQL Server 5.7\my.cnf
C:\Program Files\MySQL\MySQL Server 5.7\my.ini
C:\Program Files\php\php.ini
C:\Users\Administrator\NTUser.dat
C:\Windows\debug\NetSetup.LOG
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\php.ini
C:\Windows\repair\SAM
C:\Windows\repair\system
C:\Windows\System32\config\AppEvent.evt
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\system
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SecEvent.evt
C:\Windows\System32\config\SysEvent.evt
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\win.ini 
C:\xampp\apache\conf\extra\httpd-xampp.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\FileZillaFTP\FileZilla Server.xml
C:\xampp\MercuryMail\MERCURY.INI
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\security\webdav.htpasswd
C:\xampp\sendmail\sendmail.ini
C:\xampp\tomcat\conf\server.xml
```

## Old IIS vulnerabilities worth looking for

### Microsoft IIS tilde character “~” Vulnerability/Feature – Short File/Folder Name Disclosure

You can try to **enumerate folders and files** inside every discovered folder \(even if it's requiring Basic Authentication\) using this **technique**.  
The main limitation of this technique if the server is vulnerable is that **it can only find up to the first 6 letters of the name of each file/folder and the first 3 letters of the extension** of the files.

You can use [https://github.com/irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner) to test for this vulnerability:`java -jar iis_shortname_scanner.jar 2 20 http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/`

![](../../.gitbook/assets/image%20%28161%29.png)

Original research: [https://soroush.secproject.com/downloadable/microsoft\_iis\_tilde\_character\_vulnerability\_feature.pdf](https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf)

You can also use **metasploit**: `use scanner/http/iis_shortname_scanner`

### Basic Authentication bypass

**Bypass** a Baisc authentication \(**IIS 7.5**\) trying to access: `/admin:$i30:$INDEX_ALLOCATION/admin.php` or `/admin::$INDEX_ALLOCATION/admin.php`

You can try to **mix** this **vulnerability** and the last one to find new **folders** and **bypass** the authentication.

