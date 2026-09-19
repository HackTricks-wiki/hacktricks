# Privacy Operating Systems

{{#include ../banners/hacktricks-training.md}}

Privacy-focused operating systems reduce routing and persistence mistakes, but none can compensate for identifying behavior or compromised hardware.

## Choose the isolation model

| System | Best fit | Persistence | Network enforcement | Main tradeoff |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Occasional anonymous web browsing | Browser state normally session-scoped | Browser traffic only | Other apps and host remain outside Tor |
| **Tails** | Portable, amnesic, single-purpose sessions | Optional encrypted Persistent Storage | Internet traffic forced through Tor | Reboots/workflow friction; firmware/hardware trust |
| **Whonix** | Persistent applications that need forced Tor routing | Persistent VMs | Gateway/workstation split | Host/hypervisor and identity mixing remain |
| **Qubes-Whonix** | Strong compartment separation for advanced users | Per-qube | Dedicated network qubes and Whonix | Hardware requirements and operational complexity |

## Tails

Tails boots independently from removable media, routes Internet traffic through Tor, and is designed to leave minimal local state. Its own warnings emphasize that it cannot protect against a compromised BIOS/firmware/hardware, identifying disclosures, file metadata, or a powerful observer correlating both ends.<sup>[[1]](#references)</sup>

### Single-purpose Tails workflow

1. Download Tails from the official site on a trusted, updated computer and follow the official verification/install process.
2. Use a supported USB drive only for booting Tails; do not also use it as a general file-transfer drive.
3. Boot on hardware you physically control. A live OS cannot neutralize a hardware keylogger or malicious firmware.
4. Leave Persistent Storage disabled unless the workflow truly needs it. If enabled, persist only required categories and use a strong passphrase.
5. Connect to a lawful network. If a captive portal is unavoidable, use Tails' Unsafe Browser only for the portal, disclose no unnecessary identity, close it immediately, and connect to Tor before any sensitive activity.<sup>[[2]](#references)</sup>
6. Configure a Tor bridge if direct Tor visibility or blocking matters.
7. Perform **one contextual identity/purpose per session**. Tails recommends restarting between activities that should not be linked.<sup>[[1]](#references)</sup>
8. Inspect and sanitize files before publishing. Do not open downloaded active documents in an application that could bypass the intended context.
9. Shut down fully when finished and keep the USB physically secure.

## Whonix

Whonix separates a Tor-routing **Gateway** from a **Workstation** whose applications cannot directly learn the external IP. This meaningfully reduces proxy/DNS mistakes, but the host, hypervisor, behavior, and documents can still reveal identity. Whonix explicitly warns against using one workstation for multiple identities or combining anonymous and non-anonymous activity.<sup>[[3]](#references)</sup>

### Compartment workflow

1. Verify the Whonix image and virtualization platform from official sources.
2. Patch the host, hypervisor, Gateway, and Workstation before use.
3. Clone a fresh Workstation for each identity or engagement; never clone a VM after identity-bearing state has been introduced.
4. Keep personal accounts, host shared folders, clipboard synchronization, USB devices, and time/location data out of the Workstation.
5. Use snapshots for recovery, not as a substitute for backups or identity separation.
6. Confirm the Workstation cannot reach the Internet when the Gateway is stopped.
7. For especially risky files, use a disposable VM/qube and export only a sanitized result.

## Qubes OS and Qubes-Whonix

Qubes implements security by compartmentalization with Xen-backed qubes. Its design limits a compromise in one domain from automatically reaching others, but applications inside the **same** qube are not isolated from each other.<sup>[[4]](#references)</sup> Disposable qubes provide fresh state for untrusted sites, files, and devices.<sup>[[5]](#references)</sup>

A practical layout:

```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```

Rules:

- Give each qube one trust level and identity purpose.
- Keep secrets in an offline vault qube and use explicit inter-qube copy/file operations.
- Open unsolicited files and links in disposables.
- Route only the intended qubes through Whonix or a dedicated VPN qube.
- Label windows distinctly and stop unrelated qubes during sensitive work.
- Do not assume two qubes prevent correlation if they share accounts, content, schedules, or payments.

## Verification and maintenance

- Verify installer signatures/checksums through official instructions.
- Patch templates first, then restart dependent qubes/VMs.
- Confirm network-deny behavior, DNS, IPv6, clock, clipboard, shared directories, and USB assignment.
- Review Persistent Storage and VM snapshots for old identity-bearing data.
- Keep encrypted offline backups of seeds/keys and test restoration in an isolated environment.
- Rebuild a compartment after suspected compromise; changing its egress IP is insufficient.

## References

- [1] [Tails — Warnings: Tails is safe but not magic](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Signing in to a network using a captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix and Tor limitations](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Security design goals](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — How to use disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
