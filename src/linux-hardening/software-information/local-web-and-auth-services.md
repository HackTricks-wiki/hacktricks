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

## Gogs repository file writes

For a local Gogs service, correlate the `gogs web` process owner with the executable version and `custom/conf/app.ini`. The configuration can reveal the service identity, repository root, listener address, and whether registration is disabled. A loopback-only listener is still reachable by local users. Gogs versions through 0.13.3 have an authenticated `PutContents` symlink file-write issue ([CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)): a repository writer can commit a symlink and then direct the API write through it. The resulting file access has the privileges of the Gogs process, so a root-owned instance needs prompt attention. Validate the deployed fix and authentication requirements before claiming a usable path; an API error does not prove that the file write failed.

## Cobbler provisioning API

Cobbler's management service exposes an XML-RPC API, commonly on port `25151`. Check the listener and the `cobblerd` process owner before assessing its impact; a loopback-only API can still be reached by a user on the host. Review the authentication and authorization modules in `/etc/cobbler/modules.conf`, the service settings in `/etc/cobbler/settings` or `/etc/cobbler/settings.yaml`, and permissions on `/etc/cobbler/users.conf`, `/etc/cobbler/users.digest`, and `/var/lib/cobbler/web.ss`. The digest and shared-secret files contain credential material, so record their readability without printing their contents by default.

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** is an XML-RPC authentication bypass in Cobbler 3.0.0 through 3.2.2 and 3.3.0 through 3.3.6. A shared-secret read error returned the predictable value `-1`, which the API accepted as a password. The corresponding fixes are 3.2.3 and 3.3.7. A package version is a lead; verify the deployed code and any backported fix before reporting exposure.

An authenticated API session can be a privileged execution path when `cobblerd` runs as root. In affected implementations, `background_import` passes user-controlled `rsync_flags` into a shell command, and rendering a user-controlled Cheetah autoinstall template can evaluate Python. Check the API permissions and installed version before testing either path. Restrict access to the management API, patch the authentication bypass, and keep configuration and credential files readable only by the service administrators.

## Motion and motionEye configuration

Inspect `/etc/motioneye/motioneye.conf` for `conf_path`, then review `motion.conf` and a small number of `camera-*.conf` files in that directory. Report whether a readable `# @admin_password` hash exists without printing it. [Older motionEye releases wrote these files with broad read permissions](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67); the fix is in 0.44.0. Check the Motion `webcontrol_port`, `webcontrol_parms`, `webcontrol_auth_method`, and `webcontrol_localhost` settings together: advanced control (`2` or `3`) with disabled authentication can expose powerful operations to a local user, including on a loopback listener. [Motion documents the values and defaults](https://motion-project.github.io/motion_config.html).

An admin session against motionEye before 0.43.1b5 could turn a camera filename setting into command execution when Motion processed it ([CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)). Confirm the running version, service identity, usable authentication path, and whether a camera is configured before claiming an escalation. Configuration alone does not prove the service is running or privileged.

A service name or installed package is only a lead. The privilege boundary is the combination of reachable input, process identity, writable configuration, and the command or file it ultimately controls.
{{#include ../../banners/hacktricks-training.md}}
