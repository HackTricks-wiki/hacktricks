# Software Information

{{#include ../../banners/hacktricks-training.md}}

Installed software adds authentication hooks, management interfaces, and service-specific behavior to a Linux host. Identify the installed component and its privileges, then review the relevant page:

- [Local web and authentication services](local-web-and-auth-services.md) maps host-side web, proxy, PAM, LDAP, mail, and CI surfaces.
- [Databases and secret material](databases-and-secret-material.md) covers local DB endpoints, application configs, key stores, and tokens.
- [PAM: Pluggable Authentication Modules](pam-pluggable-authentication-modules.md) covers Linux authentication modules and configuration.
- [FreeIPA pentesting](freeipa-pentesting.md) covers identity-management deployments.
- [Logstash](logstash.md) covers service-specific attack surfaces.
- [Splunk LPE and persistence](splunk-lpe-and-persistence.md) covers local escalation and persistence paths in Splunk deployments.
- [Node inspector and CEF debugger abuse](electron-cef-chromium-debugger-abuse.md) covers exposed debugging interfaces.
- [Android rooting-framework manager authentication bypass and syscall hooks](../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md) covers local app-to-root escalation on already-rooted Android devices; its Android-specific prerequisites live with Mobile Pentesting.
{{#include ../../banners/hacktricks-training.md}}
