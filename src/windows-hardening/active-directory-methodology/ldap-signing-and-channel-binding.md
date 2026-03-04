# LDAP Signing & Channel Binding Ojačavanje

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno

LDAP relay/MITM omogućava napadačima da proslede binds ka Domain Controllers kako bi dobili autentifikovane kontekste. Dve serverske kontrole zatvaraju ove puteve:

- **LDAP Channel Binding (CBT)** veže LDAPS bind za specifični TLS tunel, onemogućavajući relays/replays preko različitih kanala.
- **LDAP Signing** primorava LDAP poruke zaštićene integritetom, sprečavajući tampering i većinu unsigned relays.

**Brza ofanzivna provera**: alati poput `netexec ldap <dc> -u user -p pass` ispisuju stav servera. Ako vidite `(signing:None)` i `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** su izvodljivi (npr. koristeći KrbRelayUp za upis `msDS-AllowedToActOnBehalfOfOtherIdentity` za RBCD i impersonaciju administratora).

**Server 2025 DCs** uvode novi GPO (**LDAP server signing requirements Enforcement**) koji podrazumevano zahteva **Require Signing** ako je ostavljen kao **Not Configured**. Da biste izbegli primenu (enforcement), morate eksplicitno postaviti tu politiku na **Disabled**.

## LDAP Channel Binding (LDAPS samo)

- **Zahtevi**:
- Patch za CVE-2017-8563 (2017) dodaje podršku za Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) dodaje LDAPS CBT “what-if” telemetriju.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: postavite **When Supported** da evidentira:
- **3074** – LDAPS bind bi pao CBT validaciju da je enforcement bio uključen.
- **3075** – LDAPS bind je izostavio CBT podatke i bio bi odbijen da je enforcement uključen.
- (Event **3039** i dalje signalizira CBT neuspehe na starijim build-ovima.)
- **Enforcement**: postavite **Always** kada LDAPS klijenti šalju CBT; deluje samo na **LDAPS** (not raw 389).

## LDAP Signing

- **GPO klijenta**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: ostavite legacy politiku na `None` i postavite `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it).
- **Kompatibilnost**: samo Windows **XP SP3+** podržava LDAP signing; stariji sistemi će prestati da rade kada je enforcement omogućen.

## Uvođenje sa auditom (preporučeno ~30 dana)

1. Omogućite LDAP interface diagnostics na svakom DC da evidentira unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Postavite DC GPO `LDAP server channel binding token requirements` = **When Supported** da biste pokrenuli CBT telemetriju.
3. Pratite Directory Service događaje:
- **2889** – unsigned/unsigned-allow binds (neusklađeno sa potpisivanjem).
- **3074/3075** – LDAPS binds that would fail or omit CBT (requires KB4520412 on 2019/2022 and step 2 above).
4. Sprovodite u odvojenim promenama:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Izvori

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
