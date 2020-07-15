# JBOSS

## Enumeration

The _/web-console/ServerInfo.jsp_ and _/status?full=true_ web pages often reveal **server details**.

You can expose **management servlets** via the following paths within JBoss \(depending on the version\): _/admin-console_, _/jmx-console_, _/management_, and _/web-console_. Default credentials are **admin**/**admin**. Upon gaining access, you can use available invoker servlets to interact with exposed MBeans:

* /web-console/Invoker \(JBoss versions 6 and 7\)
* /invoker/JMXInvokerServlet and /invoker/EJBInvokerServlet \(JBoss 5 and prior\)

**You can enumerate and even exploit a JBOSS service using** [**clusterd**](https://github.com/hatRiot/clusterd)  
**Or using metasploit:** `msf > use auxiliary/scanner/http/jboss_vulnscan`

### Exploitation

[https://github.com/joaomatosf/jexboss](https://github.com/joaomatosf/jexboss)

### Google Dork

```text
inurl:status EJInvokerServlet
```

