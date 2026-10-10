# Informations sur les logiciels

{{#include ../../banners/hacktricks-training.md}}

Les logiciels installés ajoutent des hooks d’authentification, des interfaces de gestion et des comportements propres aux services sur un hôte Linux. Identifiez le composant installé et ses privilèges, puis consultez la page correspondante :

- [Services web locaux et d’authentification](local-web-and-auth-services.md) répertorie les surfaces côté hôte liées au web, aux proxys, à PAM, à LDAP, aux e-mails et à la CI.
- [Bases de données et secrets](databases-and-secret-material.md) couvre les endpoints DB locaux, les configurations d’applications, les keystores et les tokens.
- [PAM : modules d’authentification enfichables](pam-pluggable-authentication-modules.md) couvre les modules d’authentification Linux et leur configuration.
- [Pentesting de FreeIPA](freeipa-pentesting.md) couvre les déploiements de gestion des identités.
- [Logstash](logstash.md) couvre les surfaces d’attaque propres au service.
- [LPE et persistance dans Splunk](splunk-lpe-and-persistence.md) couvre les voies d’escalade locale et de persistance dans les déploiements Splunk.
- [Abus de Node inspector et du débogueur CEF](electron-cef-chromium-debugger-abuse.md) couvre les interfaces de débogage exposées.
- [Contournement de l’authentification du gestionnaire de frameworks de rooting Android et hooks syscall](android-rooting-frameworks-manager-auth-bypass-syscall-hook.md) couvre cette pile logicielle spécialisée basée sur Linux.
{{#include ../../banners/hacktricks-training.md}}
