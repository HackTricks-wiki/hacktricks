# Industrial Control Systems Hacking

{{#include ../../banners/hacktricks-training.md}}

## About This Section

This section introduces industrial control system (ICS) components, architectures, protocols, and security-assessment methods. ICS is part of the broader operational technology (OT) domain: programmable systems and devices that monitor or cause changes in physical processes. Common examples include supervisory control and data acquisition (SCADA) systems, distributed control systems (DCSs), and programmable logic controllers (PLCs).<sup>[[1]](#references)</sup>

Security work in these environments must account for requirements that differ from conventional IT, including process safety, reliability, availability, deterministic operation, and equipment lifecycles. A technically valid security control may still be unsuitable if it disrupts the physical process, so testing and remediation should be coordinated with the system owner and operations personnel.<sup>[[1]](#references)</sup>

Compromise or accidental disruption can stop production, damage equipment, release hazardous material, harm the environment, or cause injury and loss of life. This potential physical impact is why understanding the controlled process and its safe operating limits must come before active testing.<sup>[[1]](#references)</sup>

Many OT deployments retain legacy operating systems, applications, and protocols because equipment has a long service life and changes require operational and safety testing. Some protocols were designed without modern authentication or encryption, and patching may be constrained by vendor support or maintenance windows; compensate with segmentation, access control, and monitoring where direct upgrades are not feasible.<sup>[[1]](#references)</sup>

## Assessment Priorities

Begin by understanding the controlled process, system boundaries, network topology, assets, data flows, trust relationships, and external connections. Similar device types can serve different functions across sites, so avoid assuming that one deployment's architecture or impact model applies to another.<sup>[[1]](#references)</sup>

Prefer passive discovery and existing engineering documentation where possible. Any active scanning or exploitation should follow an approved test plan that defines safety constraints, maintenance windows, recovery procedures, and stop conditions. Findings should be evaluated for both cybersecurity impact and potential effects on the physical process.<sup>[[1]](#references)</sup>

The same architectural knowledge supports defensive activities such as asset inventory, network segmentation, monitoring, incident response, and risk-based vulnerability management.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Guide to Operational Technology (OT) Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)

{{#include ../../banners/hacktricks-training.md}}
