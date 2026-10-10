# Indicatori di escalation di sessione e del servizio disco in SUSE

{{#include ../../banners/hacktricks-training.md}}

## Autorizzazione della sessione SSH tramite PAM

CVE-2025-6018 ha interessato le configurazioni PAM di SUSE 15 in cui uno stack di autenticazione SSH caricava `pam_env` prima che lo stack di sessione caricasse `pam_systemd`. Quando `pam_env` leggeva il file `.pam_environment` di un utente, quest'ultimo poteva fornire valori `XDG_SEAT` e `XDG_VTNR` che facevano apparire a Polkit una sessione SSH come fisicamente attiva. In questo modo, un'azione `allow_active=yes` poteva diventare disponibile per un utente remoto. Ciò modifica l'autorizzazione della sessione, ma non garantisce di per sé l'accesso root. SUSE ha corretto il comportamento predefinito relativo all'ambiente utente in `pam` e la posizione del modulo generata da `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Esamina la catena di inclusioni effettiva di `/etc/pam.d/sshd`, l'ordine di `pam_env.so` e `pam_systemd.so` e l'eventuale opzione esplicita `user_readenv=1`. Un pacchetto `pam` corretto modifica il comportamento predefinito, ma un'opzione esplicita può comunque richiedere la lettura dell'ambiente utente. Un pacchetto `pam-config` più recente non dimostra che uno stack PAM modificato localmente o obsoleto sia stato rigenerato. Verifica insieme la release del pacchetto del fornitore e la configurazione effettiva.<sup>[[1]](#references)[[2]](#references)</sup>

## Percorso del servizio disco per l'utente attivo

CVE-2025-6019 era un percorso di escalation in `libblockdev` utilizzato tramite `udisks2`: durante il ridimensionamento di un filesystem XFS, un filesystem fornito dall'attaccante poteva essere montato temporaneamente senza la restrizione `nosuid` prevista. Perché il percorso sia utilizzabile, sono necessari un servizio UDisks D-Bus accessibile, il supporto al ridimensionamento XFS, un'azione Polkit pertinente disponibile per l'utente e una versione vulnerabile del pacchetto della libreria. CVE-2025-6018 è un modo per ottenere una sessione utente attivo, ma un utente già attivo può raggiungere il percorso del servizio disco in modo indipendente.<sup>[[3]](#references)</sup>

Per un'analisi passiva, verifica i metadati del servizio UDisks, la policy `org.freedesktop.udisks2.modify-device`, `xfs_growfs` e il pacchetto `libbd_fs2` installato. SUSE indica la versione `2.26-150400.3.5.1` di `libbd_fs2` come corretta per openSUSE Leap 15.6; la release corretta esatta dipende dal prodotto. La presenza della policy e del pacchetto costituisce solo un indizio, non una prova che un utente possa montare o ridimensionare un dispositivo. Durante l'enumerazione, evita di modificare i mount o invocare metodi D-Bus.<sup>[[3]](#references)</sup>

## References

- [1] [Avviso SUSE CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Aggiornamento di sicurezza SUSE per pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Avviso SUSE CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
