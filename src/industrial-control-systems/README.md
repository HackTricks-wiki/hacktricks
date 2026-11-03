# Industrial Control Systems Hacking

{{#include ../banners/hacktricks-training.md}}

## About This Section

This section introduces industrial control system (ICS) components, architectures, protocols, and security-assessment methods. ICS is part of the broader operational technology (OT) domain: programmable systems and devices that monitor or cause changes in physical processes. Common examples include supervisory control and data acquisition (SCADA) systems, distributed control systems (DCSs), and programmable logic controllers (PLCs).<sup>[[1]](#references)</sup>

Security work in these environments must account for requirements that differ from conventional IT, including process safety, reliability, availability, deterministic operation, and equipment lifecycles. A technically valid security control may still be unsuitable if it disrupts the physical process, so testing and remediation should be coordinated with the system owner and operations personnel.<sup>[[1]](#references)</sup>

Compromise or accidental disruption can stop production, damage equipment, release hazardous material, harm the environment, or cause injury and loss of life. This potential physical impact is why understanding the controlled process and its safe operating limits must come before active testing.<sup>[[1]](#references)</sup>

Many OT deployments retain legacy operating systems, applications, and protocols because equipment has a long service life and changes require operational and safety testing. Some protocols were designed without modern authentication or encryption, and patching may be constrained by vendor support or maintenance windows; compensate with segmentation, access control, and monitoring where direct upgrades are not feasible.<sup>[[1]](#references)</sup>

## Assessment Priorities

Begin by understanding the controlled process, system boundaries, network topology, assets, data flows, trust relationships, and external connections. Similar device types can serve different functions across sites, so avoid assuming that one deployment's architecture or impact model applies to another.<sup>[[1]](#references)</sup>

Prefer passive discovery and existing engineering documentation where possible. Any active scanning or exploitation should follow an approved test plan that defines safety constraints, maintenance windows, recovery procedures, and stop conditions. Findings should be evaluated for both cybersecurity impact and potential effects on the physical process.<sup>[[1]](#references)</sup>

The same architectural knowledge supports defensive activities such as asset inventory, network segmentation, monitoring, incident response, and risk-based vulnerability management.<sup>[[1]](#references)</sup>

## Supervisory refrigeration controller abuse

A refrigeration system manager coordinates compressor and case controllers but does not cool cases itself. Access to its management interface can therefore become control over many subordinate devices through normal configuration distribution. This is distinct from changing one thermostat or directly driving a compressor.<sup>[[3]](#references)[[4]](#references)</sup>

### Date-derived maintenance-code login

On affected Danfoss system managers, an alternate XML login accepts a code derived from the controller's date instead of an account password.<sup>[[2]](#references)[[3]](#references)</sup> On the SM800 and SC255, Synacktiv traced the `eds_only` and `quantum_only` attributes through `xml_load_file` and `check_authorize` to `check_code_of_day`. Its advisory also shows that `read_date_time` on `xml.cgi` discloses the controller's date without authentication.<sup>[[2]](#references)</sup> Claroty found a corresponding `getauth` path on the AK-SM 800A, but redacted its trigger attributes; the older models' attribute names should not be assumed to work on that platform.<sup>[[3]](#references)</sup>

Synacktiv documents the unauthenticated date query as follows:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

The code has no device-specific secret: recovering the algorithm from [firmware](../hardware-physical-access/firmware-analysis/) can yield a date-valid credential for devices with the same affected implementation.<sup>[[2]](#references)[[3]](#references)</sup> Confirm the model and firmware first. A date response alone does not establish that the alternate login is present or that a session was obtained.

### Bulk configuration and defrost-heater abuse

After administrative access, identify the system manager's mapped case controllers and whether its configuration-distribution function can update them together. A case setpoint change normally warms a cabinet only toward room temperature. To heat it beyond ambient, the relevant control is the case controller's electric evaporator defrost heater: defrost stops cooling and runs that heater until a sensor or timer terminates the cycle. Changing the defrost method, schedule, termination temperature, and time limit can keep the heater active instead. The manager can distribute those changes across many cases and suppress associated alarms, turning one supervisory compromise into a store-wide process change.<sup>[[4]](#references)</sup>

This is a physical-process hazard, not a safe live-system proof of concept. Where present, thermal cut-outs may limit heater operation, but continuous duty can still overheat a pre-existing weak electrical connection. Validate configuration and impact only in an approved lab or with the operator's process-safety plan.<sup>[[4]](#references)</sup>

## Protocol entry points

- [Modbus testing](../network-services-pentesting/pentesting-modbus.md) covers Modbus TCP, serial variants, function codes, and register access.
- [OPC UA testing](../network-services-pentesting/4840-pentesting-opc-ua.md) covers the industrial data-exchange service.
- [BACnet testing](../network-services-pentesting/47808-udp-bacnet.md) covers building-automation control networks.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guide to Operational Technology (OT) Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Authentication bypass in Danfoss System-Managers SM800 and SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Freeze the Controller, Defrost the Food](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - You don't need a nation state to warm up a fridge](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)

{{#include ../banners/hacktricks-training.md}}
