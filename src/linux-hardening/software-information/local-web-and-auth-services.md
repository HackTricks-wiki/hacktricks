# Local Web and Authentication Services

{{#include ../../banners/hacktricks-training.md}}

A Linux shell provides a host-side view of web and authentication services: process arguments, listeners, unit files, configuration, logs, and local-only interfaces. Use that view to connect a reachable service to the account and files it actually uses.

## Map the local web stack

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

Inspect virtual-host names, document roots, proxy routes, upload directories, PHP execution settings, and config files containing credentials. A loopback listener may be reachable through a proxy or SSH tunnel. To test a named virtual host against a local listener, send the intended `Host` header or use `curl --resolve` with the correct address and port. Virtual-host enumeration can also reveal names absent from the default response. Check whether Apache permits `.htaccess` overrides and whether upload paths can execute PHP before treating a writable upload directory as code execution. A deployed JavaScript source map may expose source paths or client-side secrets; treat recovered values as clues and verify their actual privileges. For web-specific checks, see [Apache](../../network-services-pentesting/pentesting-web/apache.md) and [Nginx](../../network-services-pentesting/pentesting-web/nginx.md).

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

Filter virtual-host results against the default response size or another stable baseline so every guessed name does not look valid. A source map is useful only if it is actually deployed or otherwise readable.

Reverse proxies can change which client headers an application trusts. Compare direct and proxied requests before assuming that `X-Forwarded-For`, `X-Forwarded-Host`, or similar headers establish a caller's identity. Review proxy and application configuration together.

## Authentication and service identities

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) governs service-specific authentication; writable policy or module paths can change login behavior.
- LDAP/SSSD configuration can reveal directory endpoints, bind identities, and access rules. A recovered bind password may permit LDAP queries beyond the current OS account; test the exact bind identity and directory ACLs. Review file permissions before inspecting secrets; [Linux Active Directory](../user-information/linux-active-directory.md) and [FreeIPA](freeipa-pentesting.md) cover ticket and directory use.
- Postfix aliases can pipe received mail to local commands. If a lower-privileged user can change the referenced script, mail delivery may trigger their code under the delivery identity. Review alias maps and script ownership before claiming that path; see [SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md).
- Jenkins and other CI services may run jobs under a powerful local account. Inspect the service user, writable job/workspace paths, and local administration interface before testing a pipeline or plugin.

A service name or installed package is only a lead. The privilege boundary is the combination of reachable input, process identity, writable configuration, and the command or file it ultimately controls.
{{#include ../../banners/hacktricks-training.md}}
