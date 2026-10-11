# Indicatori di escalation tramite sessione SUSE e servizio disco

{{#include ../../banners/hacktricks-training.md}}

## Autorizzazione delle sessioni SSH tramite PAM

CVE-2025-6018 ha interessato le configurazioni PAM di SUSE 15 in cui uno stack di autenticazione SSH caricava `pam_env` prima che lo stack della sessione caricasse `pam_systemd`. Quando `pam_env` leggeva il file `.pam_environment` di un utente, quest'ultimo poteva fornire valori `XDG_SEAT` e `XDG_VTNR` che facevano apparire una sessione SSH come fisicamente attiva a Polkit. In questo modo, un'azione `allow_active=yes` poteva diventare disponibile a un utente remoto. Questo modifica l'autorizzazione della sessione; da solo, non garantisce l'accesso root. SUSE ha corretto il comportamento predefinito relativo all'ambiente utente in `pam` e la posizione del modulo generata da `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Esamina la catena di inclusione effettiva di `/etc/pam.d/sshd`, l'ordine di `pam_env.so` e `pam_systemd.so` e l'eventuale opzione esplicita `user_readenv=1`. Un pacchetto `pam` aggiornato corregge il comportamento predefinito, ma un'opzione esplicita può comunque richiedere la lettura dell'ambiente utente. Un pacchetto `pam-config` più recente non dimostra che uno stack PAM modificato localmente o obsoleto sia stato rigenerato. Verifica sia la versione del pacchetto fornito dal vendor sia la configurazione effettiva.<sup>[[1]](#references)[[2]](#references)</sup>

## Percorso del servizio disco per un utente attivo

CVE-2025-6019 era un percorso di escalation in `libblockdev`, utilizzato tramite `udisks2`: durante il ridimensionamento di XFS, un filesystem fornito dall'attaccante poteva essere montato temporaneamente senza la restrizione `nosuid` prevista. Il percorso richiede un servizio UDisks D-Bus utilizzabile, il supporto per il ridimensionamento di XFS, un'azione Polkit pertinente disponibile al chiamante e un pacchetto della libreria vulnerabile. CVE-2025-6018 è un modo per ottenere una sessione utente attiva, ma un utente già attivo può raggiungere indipendentemente il percorso del servizio disco.<sup>[[3]](#references)</sup>

Per un'analisi passiva, verifica i metadati del servizio UDisks, la policy `org.freedesktop.udisks2.modify-device`, `xfs_growfs` e il pacchetto `libbd_fs2` installato. SUSE indica la versione `2.26-150400.3.5.1` di `libbd_fs2` come corretta per openSUSE Leap 15.6; la versione esatta della correzione dipende dal prodotto. La presenza della policy e del pacchetto costituisce solo un indizio, non prova che un chiamante possa montare o ridimensionare un dispositivo. Evita di modificare i mount o invocare metodi D-Bus durante l'enumerazione.<sup>[[3]](#references)</sup>

## References

- [1] [Avviso SUSE CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Aggiornamento di sicurezza SUSE pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Avviso SUSE CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
