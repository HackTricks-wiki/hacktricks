# Informazioni sul software

{{#include ../../banners/hacktricks-training.md}}

Il software installato aggiunge hook di autenticazione, interfacce di gestione e comportamenti specifici dei servizi a un host Linux. Identifica il componente installato e i suoi privilegi, quindi consulta la pagina pertinente:

- [Servizi web locali e di autenticazione](local-web-and-auth-services.md) mappa le superfici host-side relative a web, proxy, PAM, LDAP, posta e CI.
- [Database e materiale segreto](databases-and-secret-material.md) tratta gli endpoint DB locali, le configurazioni delle applicazioni, gli archivi di chiavi e i token.
- [PAM: moduli di autenticazione collegabili](pam-pluggable-authentication-modules.md) tratta i moduli di autenticazione Linux e la relativa configurazione.
- [Pentesting di FreeIPA](freeipa-pentesting.md) tratta le implementazioni di gestione delle identità.
- [Logstash](logstash.md) tratta le superfici di attacco specifiche del servizio.
- [LPE e persistenza in Splunk](splunk-lpe-and-persistence.md) tratta i percorsi di escalation locale e persistenza nelle implementazioni Splunk.
- [Abuso di Node inspector e del debugger CEF](electron-cef-chromium-debugger-abuse.md) tratta le interfacce di debug esposte.
- [Bypass dell'autenticazione del manager dei framework di rooting Android e hook syscall](../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md) tratta l'escalation locale da app a root su dispositivi Android già rooted; i prerequisiti specifici di Android sono descritti nella sezione Mobile Pentesting.

{{#include ../../banners/hacktricks-training.md}}
