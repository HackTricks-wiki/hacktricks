# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

Welcome to HackTricks' comprehensive guide on Threat Modeling! Embark on an exploration of this critical aspect of cybersecurity, where we identify, understand, and strategize against potential vulnerabilities in a system. This thread serves as a step-by-step guide packed with real-world examples, helpful software, and easy-to-understand explanations. Ideal for both novices and experienced practitioners looking to fortify their cybersecurity defenses.

### Commonly Used Scenarios

1. **Software Development**: As part of the Secure Software Development Life Cycle (SSDLC), threat modeling helps in **identifying potential sources of vulnerabilities** in the early stages of development.
2. **Penetration Testing**: The Penetration Testing Execution Standard (PTES) framework requires **threat modeling to understand the system's vulnerabilities** before carrying out the test.

### Threat Model in a Nutshell

A Threat Model is typically represented as a diagram, image, or some other form of visual illustration that depicts the planned architecture or existing build of an application. It bears resemblance to a **data flow diagram**, but the key distinction lies in its security-oriented design.

Threat models often feature elements marked in red, symbolizing potential vulnerabilities, risks, or barriers. To streamline the process of risk identification, the CIA (Confidentiality, Integrity, Availability) triad is employed, forming the basis of many threat modeling methodologies, with STRIDE being one of the most common. However, the chosen methodology can vary depending on the specific context and requirements.

### The CIA Triad

The CIA Triad is a widely recognized model in the field of information security, standing for Confidentiality, Integrity, and Availability. These three pillars form the foundation upon which many security measures and policies are built, including threat modeling methodologies.

1. **Confidentiality**: Ensuring that the data or system is not accessed by unauthorized individuals. This is a central aspect of security, requiring appropriate access controls, encryption, and other measures to prevent data breaches.
2. **Integrity**: The accuracy, consistency, and trustworthiness of the data over its lifecycle. This principle ensures that the data is not altered or tampered with by unauthorized parties. It often involves checksums, hashing, and other data verification methods.
3. **Availability**: This ensures that data and services are accessible to authorized users when needed. This often involves redundancy, fault tolerance, and high-availability configurations to keep systems running even in the face of disruptions.

### Threat Modeling Methodlogies

1. **STRIDE**: Developed by Microsoft, STRIDE is an acronym for **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Each category represents a type of threat, and this methodology is commonly used in the design phase of a program or system to identify potential threats.
2. **DREAD**: This is another methodology from Microsoft used for risk assessment of identified threats. DREAD stands for **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Each of these factors is scored, and the result is used to prioritize identified threats.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): This is a seven-step, **risk-centric** methodology. It includes defining and identifying security objectives, creating a technical scope, application decomposition, threat analysis, vulnerability analysis, and risk/triage assessment.
4. **Trike**: This is a risk-based methodology that focuses on defending assets. It starts from a **risk management** perspective and looks at threats and vulnerabilities in that context.
5. **VAST** (Visual, Agile, and Simple Threat modeling): This approach aims to be more accessible and integrates into Agile development environments. It combines elements from the other methodologies and focuses on **visual representations of threats**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Developed by the CERT Coordination Center, this framework is geared toward **organizational risk assessment rather than specific systems or software**.

## Tools

There are several tools and software solutions available that can **assist** with the creation and management of threat models. Here are a few you might consider.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

An advance cross-platform and multi-feature GUI web spider/crawler for cyber security professionals. Spider Suite can be used for attack surface mapping and analysis.

**Usage**

1. Pick a URL and Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. View Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

An open-source project from OWASP, Threat Dragon is both a web and desktop application that includes system diagramming as well as a rule engine to auto-generate threats/mitigations.

**Usage**

1. Create New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Sometimes it could look like this:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Launch New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Save The New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Create your model

You can use tools like SpiderSuite Crawler to give you inspiration, a basic model would look something like this

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Just a little bit of explanation about the entities:

- Process (The entity itself such as Webserver or web functionality)
- Actor (A Person such as a Website Visitor, User or Administrator)
- Data Flow Line (Indicator of Interaction)
- Trust Boundary (Different network segments or scopes.)
- Store (Things where data are stored at such as Databases)

5. Create a Threat (Step 1)

First you have to pick the layer you wish to add a threat to

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Now you can create the threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Keep in mind that there is a difference between Actor Threats and Process Threats. If you would add a threat to an Actor then you will only be able to choose "Spoofing" and "Repudiation. However in our example we add threat to a Process entity so we will see this in the threat creation box:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Done

Now your finished model should look something like this. And this is how you make a simple threat model with OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

This is a free tool from Microsoft that helps in finding threats in the design phase of software projects. It uses the STRIDE methodology and is particularly suitable for those developing on Microsoft's stack.

## TEE / Confidential Computing Threat Modeling

When assessing a **TEE / Confidential VM** design, the main mistake is usually to trust the attestation boundary more than the actual **measured boundary**. If some input can still influence execution but is **not** covered by the attested measurement, that input must be modeled as attacker-controlled.

### Questions to ask

- What data is loaded **after** the measurement is taken?
- Which boot artifacts are consumed by the guest but not cryptographically measured or verified?
- Is the attestation bound to the **current session**, or can it be replayed?
- Is the platform version / patch level verified from **vendor-signed metadata**, or only from mutable values reported by firmware?
- Can the host, hypervisor, cloud operator, or provisioning pipeline tamper with any of these inputs?

### High-value TEE attack paths

#### Post-measurement configuration injection

If configuration is loaded after attestation, it can change enclave/CVM behaviour without changing the attestation value. Treat env vars, config files, mounted secrets, and late-loaded arguments as hostile unless they are measured or strictly validated.

Example dangerous input:

```bash
LD_PRELOAD=/path/to/evil.so
```

If this is accepted from an unmeasured config source, attacker code executes **inside** the trusted boundary while clients still see a valid attestation.

Review points:
- Deny dangerous loader variables such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `LD_AUDIT`.
- Allow only strict character sets / schemas for runtime config values.
- Prefer measuring boot-time config instead of trusting host-provided runtime files.

#### Unmeasured hardware-description injection

ACPI tables, device trees, initrd content, and similar host-supplied boot metadata can redefine the effective hardware exposed to the guest. If these artifacts are not verified/measured, a malicious hypervisor may present fake devices with unexpected DMA or memory access.

Review points:
- Check whether ACPI tables and other hardware-description blobs are part of the measured boot chain.
- Verify signatures on boot metadata before the guest trusts it.
- Model malicious virtual devices as a path to **guest memory disclosure** and key extraction.

#### Patch-level spoofing

Do not trust the patch level that firmware merely **claims** in an attestation report. A downgraded or vulnerable platform may lie about its version and still pass naive validation.

Review points:
- For AMD SEV-SNP, validate TCB / patch claims against **AMD-signed VCEK certificate X.509 extensions**.
- Reject attestations that satisfy measurement checks but fail minimum platform-version policy.
- Test downgrade scenarios with older firmware to make sure the verifier rejects spoofed claims.

#### Attestation replay without freshness

An attestation that is not bound to the current connection can be replayed. This turns a one-time TEE compromise or key leak into persistent impersonation.

Review points:
- Bind attestation to a client nonce, ideally the TLS `client_random`, or another verifier-chosen challenge.
- Require timestamps / expiration checks if the protocol supports them.
- Ensure a stolen attestation blob cannot be reused across sessions, regions, or hosts.

### Negative-testing ideas

- Boot the workload with tampered post-measurement config and confirm attestation verification or startup validation fails.
- Inject malformed or unsigned ACPI tables / boot metadata and confirm the guest refuses to boot or the attestation changes.
- Replay a previously captured attestation against a fresh TLS session and confirm the verifier rejects it.
- Present an attestation from an older platform that lies about patch level and confirm policy enforcement uses vendor-signed metadata instead of firmware claims.

## References

- [Trail of Bits - What we learned about TEE security from auditing WhatsApp's Private Inference](https://blog.trailofbits.com/2026/04/07/what-we-learned-about-tee-security-from-auditing-whatsapps-private-inference/)
- [Trail of Bits - Meta/WhatsApp Private Processing security review (PDF)](https://github.com/trailofbits/publications/blob/master/reviews/2025-08-meta-whatsapp-privateprocessing-securityreview.pdf)

{{#include ../banners/hacktricks-training.md}}
