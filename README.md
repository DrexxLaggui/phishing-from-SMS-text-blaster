# phishing-from-SMS-text-blaster
Identity (IMSI / IMEI) requested in suspicious manner v3; Disconnected after Identity Request without Auth Accept (packet 108896)
<img width="729" height="341" alt="BDO-CPH-phshing_Rayhunter-1763879463_Drexx-202511124" src="https://github.com/user-attachments/assets/739d27fa-c575-45be-acf4-261ba9ee4b8f" />

# LTE NAS Anomaly — Identity Request → Attach Reject (Cause 15)
**Date:** 2025-11-24 • **Network:** Smart (PH) • **Capture device:** TP-Link M7350 (Rayhunter 0.7.1, QMDL)  

## Summary

On **24 November 2025**, my TP-Link M7350 mobile hotspot running **Rayhunter** (a passive LTE monitoring tool) recorded a sequence of messages between the hotspot (my device) and a nearby base station.  

The sequence shows that:

- My device tried three times to request normal mobile data service.
- Instead of completing the normal security and authentication steps, the network suddenly asked for my **permanent identity** (IMSI/IMEI) in the clear.
- Immediately after getting that identity, the network **rejected the connection** with a cause code that effectively leaves the device without service in that area.
- About **30 minutes later**, a **different phone** of mine received an **SMS phishing message**.

This pattern is **consistent with known “identity-harvesting” behavior** used by **rogue base stations / IMSI catchers / SMS blasters**, rather than a normal mobile operator providing service.

---

## Timeline of the Suspicious Network Behaviour

All times are local (UTC+8, Quezon City).

The following frames are LTE control messages (NAS-EPS over GSMTAP) between my hotspot and a cell claiming to be part of a mobile network:

1. **Frame 108677 — 15:04:30.162989**
   - My device sends a **Service Request** to the network.
   - This message is **integrity-protected**, meaning it is cryptographically signed so the network can verify it is genuine and untampered.
   - In normal operation, the network should respond by authenticating the device (Authentication Request), setting up security (Security Mode Command), and then granting service.

2. **Frame 108743 — 15:04:56.723998**  
   3. **Frame 108812 — 15:05:23.602999**
   - The device sends **two more Service Requests**, again integrity-protected.
   - This shows the UE (my hotspot) is repeatedly asking for legitimate service in that cell.

3. **Frame 108896 — 15:06:25.064265**
   - Instead of continuing the normal attach/authentication procedure, the network:
     1. Sends a **plain (unprotected) Identity Request** — this is a downlink message asking the device to reveal a **permanent identifier**, such as:
        - **IMSI** (International Mobile Subscriber Identity  --  uniquely identifies the SIM/subscriber), or  
        - **IMEI** (International Mobile Equipment Identity  --  identifies the device hardware).   
     2. Then sends an **Attach Reject** with **cause code 15** (“No suitable cells in tracking area”).
     3. $ tshark -r extracted/20251124a-PH-QCTY_1763879463.pcap -Y 'frame.number == 108896' -O nas-eps,lte-rrc,lte-rrc.bcch.bch,lte-rrc.bcch.dl-sch  -V 
        Frame 108896: Packet, 61 bytes on wire (488 bits), 61 bytes captured (488 bits)
        Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)
        Internet Protocol Version 4, Src: localhost (127.0.0.1), Dst: localhost (127.0.0.1)
        User Datagram Protocol, Src Port: 13337 (13337), Dst Port: gsmtap (4729)
        GSM TAP Header, ARFCN: 0 (Downlink), TS: 0, Channel: UNKNOWN (0)
        Non-Access-Stratum (NAS)PDU
          0000 .... = Security header type: Plain NAS message, not security protected (0)
          .... 0111 = Protocol discriminator: EPS mobility management messages (0x7)
          NAS EPS Mobility Management Message Type: Attach reject (0x44)
          EMM cause
            Cause: No Suitable Cells In tracking area (15)

   - The end result:  
     - the device has already disclosed its permanent identity,  
     - **but is denied service** and told there are “no suitable cells” in that area, even though signal clearly exists (because these messages are exchanged).

---

## Why This Behaviour is Abnormal

### 1. Normal LTE behaviour (legitimate network)

In a legitimate 4G/LTE network, when a device requests service:

1. The device sends an **Attach Request / Service Request** with a temporary identity if possible (to protect privacy).
2. If the network needs the permanent identity (e.g. IMSI), it can send an **Identity Request**, but then:
   - It should follow up with **Authentication Request**,  
   - Then **Security Mode Command**,  
   - Then **Attach Accept / Service Accept**, completing the procedure so the device gets service.   

**Key point:** A legitimate network that has just asked for and received a permanent identity does **not normally stop there**. It uses that identity to authenticate the subscriber and provide service (or clearly reject for a subscription reason, not just “no suitable cells”).

### 2. What happened here

Instead, the observed sequence is:

1. Multiple **integrity-protected Service Requests** from my device (legitimate attempts to get service).
2. The network **does not** proceed with Authentication or Security Mode.
3. The network then sends:
   - an **unprotected Identity Request** asking for permanent identification, and 
   - immediately afterwards, an **Attach Reject (cause 15)** effectively telling the device it cannot use that area.

This is technically **allowed** by the standards (cause 15 means “no suitable cells in tracking area”), but in combination with the explicit Identity Request and the immediate drop, it has **no clear benefit to a genuine subscriber**. It *does*, however, match a pattern documented in academic and security research on **IMSI catchers and rogue base stations**.   

In plain language:

> The fake cell site got enough information to uniquely identify my SIM/device, then immediately refused to provide service and told my device to go away.

---

<img width="1183" height="496" alt="20251124a-PH-QCTY_1763879463_OpenCellID--Timog-Ave" src="https://github.com/user-attachments/assets/b2c389c6-46a4-42b5-b37b-22cfc46fe55e" />

## Known “Identity Harvesting” / IMSI-Catcher Pattern

Technical literature on **IMSI catchers** (also called **SMS text blasters** or **cell-site simulators** or **rogue base stations**) describes the following behaviour:

- The fake base station advertises itself as a normal cell so phones try to connect.
- It uses messages such as **Identity Request** to force phones to reveal their **IMSI** (subscriber ID) or **IMEI**.   
- After collecting these identifiers, the rogue cell:
  - may **reject the attach** (e.g., using Attach Reject / TAU Reject with a cause like “no suitable cells”), or  
  - otherwise **drops the device**, so the phone moves back to the real network.   

This allows the attacker to:

- Build a list of device and subscriber identities present in a location at a given time.
- Potentially cross-reference those identities with other data sources (e.g., customer databases, previous breaches, or SMS/voice marketing lists).

The pattern recorded by Rayhunter — **Identity Request followed by immediate Attach Reject (cause 15), with no attempt to complete authentication or provide service** — is **consistent with this identity-harvesting behaviour**.

---

## Connection to the SMS Phishing Message

Approximately **30 minutes after** this incident:

- A **different phone that I own** (not the TP-Link hotspot, but another handset with its own SIM) received an **SMS phishing message**.
- The content of the SMS was unsolicited and clearly fraudulent/phishing in nature.

I cannot *prove* from the PCAP alone that:

- the same actor who operated the suspicious cell also sent the phishing SMS; or  
- that the harvested identity from my hotspot was directly linked to the phone number that received the SMS.

However, from an evidentiary standpoint:

- The **timing** (only about half an hour later),
- The **presence of a base station behaving like known identity-harvesting equipment**, and
- The **appearance of targeted phishing** shortly afterwards

together provide **strong circumstantial evidence** of a **coordinated operation to collect subscriber identities and then deliver phishing SMS messages** to devices in that area.

---

## Conclusion
   - The captured signalling strongly **suggests the presence of a base station (or network element) that was more interested in collecting device/subscriber identities than in providing service.**
   - This behaviour is **consistent with published descriptions of IMSI catchers and rogue base stations**, and **inconsistent with how a normal mobile operator is expected to handle customer connections.**
