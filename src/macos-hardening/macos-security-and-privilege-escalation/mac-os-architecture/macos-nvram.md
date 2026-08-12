# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**NVRAM** (Non-Volatile Random-Access Memory) stores firmware and early-boot state outside the normal macOS filesystem. Its security impact depends on both the variable and the boot architecture:

| Variable | Purpose / security relevance |
|---|---|
| `boot-args` | Arguments offered to the kernel. Debug or security-reducing arguments are filtered unless the boot policy permits them. |
| `csr-active-config` | SIP bitmask on Intel Macs. On Apple silicon, the equivalent policy is carried in the per-volume `LocalPolicy`, not trusted directly from this variable. |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI boot target. |
| `boot-volume` | Apple silicon boot-volume selection state. |
| `SystemAudioVolume`, `prev-lang:kbd` | Examples of ordinary persistent settings. |

The important distinction is between **data stored in NVRAM** and a **security policy accepted by the boot chain**. On Apple silicon, the Secure Enclave signs a per-boot-volume-group `LocalPolicy`; a nonce held in the Secure Storage Component provides anti-replay. Consequently, changing a similarly named NVRAM property does not by itself rewrite the accepted boot policy.<sup>[[1]](#references)[[4]](#references)</sup>

## NVRAM Access from User Space

### Reading and Baseline Collection

```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```

Do not classify every unfamiliar key as malicious. Hardware, recoveryOS, updates, Find My and boot failures all create model- and version-dependent variables. Compare a capture with an earlier baseline from the **same Mac**, and treat unexpected binary blobs, changed boot selection, or security-reducing arguments as leads rather than proof of compromise.

### Writing NVRAM

Root can create or change many ordinary variables, but protected variables additionally depend on the variable namespace, SIP, per-variable kernel rules and restricted Apple entitlements. Therefore, `sudo` succeeding for a harmless custom key does **not** prove that the process can modify `boot-args`, SIP or system-region variables.

```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```

> [!CAUTION]
> Avoid `nvram -c` during testing: it requests deletion of all deletable variables and can change boot/recovery behavior. Some variables are kernel-only, entitlement-protected, hidden on read, or only deletable during an NVRAM reset.

## NVRAM Entitlements and `CS_NVRAM_UNRESTRICTED`

At exec time XNU maps `com.apple.rootless.restricted-nvram-variables.heritable` to the process flag **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). This is not equivalent to the ordinary effective UID 0 check. There are also narrower private entitlements for particular variables or operations.

Inspect the entitlements rather than relying on the generic flags line printed by `codesign`:

```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
  grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```

When auditing a privileged helper, trace the **actual client identity and request path**. A confused-deputy bug in an entitled service can be more useful than invoking `nvram` directly, but the reachable variable/operation may still be restricted by XNU.

## Intel SIP State vs Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

On Intel, `csr-active-config` encodes the `CSR_ALLOW_*` exceptions. The commonly relevant bit positions are:

```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```

Read the effective setting with `csrutil status`; raw `nvram` output may use percent-encoded little-endian bytes. See [macOS SIP](../macos-security-protections/macos-sip.md) for the protection and bypass implications.

```bash
nvram csr-active-config 2>/dev/null
csrutil status
```

### Apple Silicon: inspect the accepted boot policy

On Apple silicon, `sip0` in the Secure Enclave-signed `LocalPolicy` holds the SIP policy bits formerly stored in NVRAM. The other relevant policy fields are `sip1` (permit an SSV root-hash verification failure), `sip2` (do not lock kernel memory with CTRR), and `sip3` (disable iBoot's `boot-args` allowlist). These fields are mutable only from paired One True recoveryOS (1TR); enabling `sip3` also requires a downgrade to Permissive Security.<sup>[[4]](#references)</sup>

Use only the display operations during enumeration:

```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```

> [!WARNING]
> Do not use `bputil` policy-changing options during an audit. A normal macOS compromise should not be able to turn the above fields on silently: the downgrade path deliberately requires physical entry into paired 1TR and owner authentication.<sup>[[4]](#references)</sup>

## Security Implications

### `boot-args` as a Post-Compromise Amplifier

Arguments such as kernel-debugging options, `kcsuffix=development`, or `amfi_get_out_of_my_way=1` can weaken later boot stages, but only when the platform accepts them. On Apple silicon in Full or Reduced Security, iBoot filters security-reducing arguments; unrestricted arguments require the `sip3` policy downgrade described above. On Intel, SIP's NVRAM restriction similarly prevents treating a root shell as automatic `boot-args` control.

```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
  grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```

See [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) and [kernel debugging](macos-kernel-extensions.md) instead of assuming that a historical argument behaves identically on every macOS release.

### NVRAM-backed `rc.trampoline` Execution

Recent research documented a concrete consumer of NVRAM data: the Apple platform binary `/System/Library/CoreServices/rc.trampoline`. When launchd sees the `rc.trampoline=1` boot argument, this boot task reads the `apple-trusted-trampoline` property from `IODeviceTree:/options`, writes it to a temporary executable, starts it suspended, checks its code-signing state, unlinks it and then resumes it. The boot task blocks launchd until the child exits.<sup>[[5]](#references)</sup>

This is a **post-downgrade persistence primitive, not a SIP bypass**. The demonstrated path required SIP to be disabled so that the boot task ran and `boot-args` could be set. The research also observed an approximate 390 KB value-size ceiling. Its value is that executable bytes can live outside the normal filesystem and be materialized during boot after an attacker has already obtained the required security downgrade.<sup>[[5]](#references)</sup>

Hunt for both required artifacts and the launchd event:

```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
  --predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```

Arbitrary custom NVRAM variables are otherwise only **storage**: they execute nothing unless firmware, an Apple boot component, or a separate persistence mechanism consumes them. This distinction avoids overstating a marker such as `nvram attacker-config=...` as firmware code execution.

## Enumeration Script

<details>
<summary>NVRAM and Apple silicon boot-policy audit</summary>

```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
  grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
  --predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
  echo '[*] Apple silicon LocalPolicy (read-only display):'
  bputil -d -j 2>&1
fi
```

</details>



## References

- [1] [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Contents of a LocalPolicy file for a Mac with Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the good ol' LaunchAgents — Persist through NVRAM with apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
