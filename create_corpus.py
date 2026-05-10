import json
import os

os.makedirs('data', exist_ok=True)

documents = [
    {
        "doc_id": "DOC001",
        "title": "AV Cybersecurity Incident Report — Sensor Fusion Attack Surface Analysis",
        "category": "incident_report",
        "sensitivity": "RESTRICTED",
        "date": "2024-03-15",
        "author": "OT Security Team",
        "content": (
            "Executive Summary: This report documents sensor fusion integrity anomalies detected "
            "across autonomous vehicle test fleets during Q1 2024. Analysis revealed coordinated "
            "evasion-based perturbation patterns targeting LiDAR and camera fusion pipelines. "
            "MITRE ATT&CK for ICS technique T0830 (Adversary-in-the-Middle) identified as primary "
            "threat vector. Affected systems include perception stacks on NVIDIA DRIVE AGX platforms. "
            "Recommendations: cryptographic attestation for sensor data streams, anomaly detection "
            "at fusion layer, OTA update integrity verification. CVE-2024-1823 identified in CAN bus "
            "arbitration protocol. Estimated remediation cost: 2.3M USD across fleet. "
            "UNECE WP.29 R155 compliance gap identified in Clause 7.2.2."
        )
    },
    {
        "doc_id": "DOC002",
        "title": "V2X Protocol Security Assessment — C-V2X vs DSRC Threat Comparison",
        "category": "technical_report",
        "sensitivity": "INTERNAL",
        "date": "2024-06-20",
        "author": "Wireless Infrastructure Team",
        "content": (
            "Technical Assessment: Comparative security analysis of Cellular V2X (C-V2X) and "
            "Dedicated Short Range Communications (DSRC) for connected vehicle deployments. "
            "C-V2X on 5.9 GHz demonstrates superior message authentication via PKI but introduces "
            "cellular network dependency risk. DSRC provides sub-10ms latency but lacks modern "
            "cryptographic primitive support. Key finding: replay attack surface is 35% larger in "
            "DSRC deployments without certificate revocation infrastructure. C-V2X PC5 mode "
            "eliminates network dependency for safety-critical messages. Recommendation: hybrid "
            "deployment with C-V2X for infrastructure coordination and DSRC for V2V safety. "
            "ISO 21434 TARA identifies 14 threat scenarios. 5G NR sidelink integration: Q3 2025."
        )
    },
    {
        "doc_id": "DOC003",
        "title": "OT/ICS Vulnerability Advisory — Automotive ECU Security Baseline",
        "category": "vulnerability_advisory",
        "sensitivity": "RESTRICTED",
        "date": "2024-09-10",
        "author": "ICS Security Team",
        "content": (
            "Advisory: Critical vulnerability assessment of ECU security baselines across "
            "production vehicle platforms. Assessment covers 47 ECU variants across powertrain, "
            "chassis, and infotainment domains. Critical findings: 23% of ECUs lack secure boot. "
            "AUTOSAR SecOC module absent in 31% of safety-critical ECUs. UDS diagnostic protocol "
            "exposes unauthenticated memory read/write in 8 ECU variants — CVE-2024-3891. "
            "CAN bus lacks message authentication in 67% of legacy platforms — MITRE ATT&CK ICS "
            "T0855. NIST SP 800-82 Rev 3 compliance: 62% of systems below minimum baseline. "
            "Remediation priority: 12 critical, 18 high, 9 medium findings. "
            "Full remediation timeline: 18 months for fleet-wide OTA deployment."
        )
    },
    {
        "doc_id": "DOC004",
        "title": "Autonomous Vehicle ML Security Framework — Q2 2024 Roadmap",
        "category": "roadmap",
        "sensitivity": "INTERNAL",
        "date": "2024-04-01",
        "author": "AI/ML Security Team",
        "content": (
            "Roadmap: 18-month initiative to establish ML security framework for AV perception "
            "and decision systems. Phase 1 (Q2-Q3 2024): stress-testing pipeline for perception "
            "models using FGSM and PGD perturbation techniques in CARLA simulation. Target: 95% "
            "detection rate for evasion-based inputs at inference time. Phase 2 (Q4 2024): "
            "runtime anomaly detection in production inference pipeline with Evidently AI drift "
            "detection. Phase 3 (Q1-Q2 2025): federated learning for privacy-preserving model "
            "updates across vehicle fleet. Differential privacy budget: epsilon=1.0. "
            "Budget allocation: 4.2M USD across 3 phases. ISO 21434 work product WP-09-05 confirmed."
        )
    },
    {
        "doc_id": "DOC005",
        "title": "Meeting Notes — OT/ICS Security Working Group Q3 2024",
        "category": "meeting_notes",
        "sensitivity": "INTERNAL",
        "date": "2024-07-18",
        "author": "Security Working Group",
        "content": (
            "Meeting Notes: OT/ICS Security Working Group — July 18, 2024. Action Items: "
            "(1) Complete NIST CSF 2.0 gap assessment by August 15 — Owner: Compliance Officer. "
            "(2) Deploy Dragos platform for OT network visibility across 3 manufacturing sites — "
            "Owner: ICS Architect. (3) Establish playbook for CAN bus injection incidents — "
            "Owner: OT Security Lead. (4) Review CISA ICS-CERT advisory ICS-24-179-01 — Owner: All. "
            "Key Discussion: Purdue Model segmentation gaps identified — Level 2 to Level 3 boundary "
            "lacks proper DMZ. Risk: lateral movement from IT to OT via historian server. "
            "MITRE ATT&CK for ICS T0886 (Remote Services) identified as active threat. "
            "Next meeting: August 15, 2024."
        )
    },
    {
        "doc_id": "DOC006",
        "title": "Product Specification — Secure OTA Update Architecture v2.1",
        "category": "product_spec",
        "sensitivity": "INTERNAL",
        "date": "2024-08-05",
        "author": "Platform Engineering",
        "content": (
            "Specification: Secure OTA update architecture for connected vehicle platforms. "
            "v2.1 introduces hardware-backed key storage via TEE on ARM TrustZone. Pipeline: "
            "(1) Package signed with HSM-backed RSA-4096. (2) SHA-3-256 hash chain verification. "
            "(3) TEE validates signature before installation. (4) Rollback protection via monotonic "
            "counter. (5) Post-update attestation to backend. Threat model addresses: package "
            "tampering, replay attacks, downgrade attacks, supply chain compromise. "
            "UNECE WP.29 R156 compliance verified. Delta update reduces bandwidth 73% for minor "
            "releases. Backend: AWS GovCloud FedRAMP High. SLA: 99.99% for safety-critical updates."
        )
    },
    {
        "doc_id": "DOC007",
        "title": "Threat Intelligence Report — Nation-State AV Infrastructure Targeting",
        "category": "threat_intel",
        "sensitivity": "RESTRICTED",
        "date": "2024-10-22",
        "author": "Threat Intelligence Team",
        "content": (
            "Intelligence Report: Nation-state threat actor activity targeting AV infrastructure. "
            "TTPs observed: spearphishing targeting Tier-1 suppliers (MITRE T1566.001), supply chain "
            "compromise of embedded software (T1195.002), living-off-the-land in OT networks (T0823). "
            "Targets: LIDAR calibration data and HD map assets. CVEs under active exploitation: "
            "CVE-2024-4521 (telematics gateway buffer overflow), CVE-2024-5893 (V2X PKI certificate "
            "validation bypass). IOCs: 23 IP addresses, 8 domains, 3 malware hashes in classified "
            "annex. Recommended mitigations: network segmentation, supplier security assessment "
            "program, threat hunting across OT/IT boundary. CISA ICS-CERT notified."
        )
    },
    {
        "doc_id": "DOC008",
        "title": "Compliance Assessment — ISO 21434 and UNECE WP.29 Gap Analysis",
        "category": "compliance",
        "sensitivity": "INTERNAL",
        "date": "2024-11-30",
        "author": "Compliance Team",
        "content": (
            "Compliance Assessment: Gap analysis against ISO 21434 and UNECE WP.29 R155/R156. "
            "ISO 21434: 78% compliance across 15 work products. Critical gaps: WP-05-01 (TARA) "
            "not completed for 3 new vehicle programs. WP-09-05 (Monitoring) lacks automated "
            "alerting. WP-10-01 (Incident Response) missing post-quantum cryptography plan. "
            "UNECE R155: 82% type approval readiness. Gaps in Clause 7.2.2 (supply chain) and "
            "7.3.3 (monitoring). UNECE R156 OTA compliance: 91%. Remediation roadmap: 14 items, "
            "9-month completion. External audit scheduled Q1 2025. "
            "NIST SP 800-82 Rev 3 alignment: 71% across OT systems."
        )
    },
    {
        "doc_id": "DOC009",
        "title": "Project Report — Digital Twin Security Simulation Platform",
        "category": "project_report",
        "sensitivity": "INTERNAL",
        "date": "2024-05-14",
        "author": "Research and Development",
        "content": (
            "Project Report: 6-month initiative to build digital twin security simulation platform "
            "for AV threat modeling. Components: CARLA v0.9.14, ROS2 Humble, SUMO, OMNeT++. "
            "Security simulations: FGSM/PGD/CW perturbation attacks, GPS spoofing, CAN bus injection, "
            "V2X message replay. Results: perception model vulnerability at epsilon=0.03 — 34% "
            "misclassification on stop sign detection. GPS spoofing detection via IMU fusion: 97% "
            "detection rate at 50m spoofing radius. Platform enables TARA automation per ISO 21434. "
            "Next phase: hardware-in-the-loop integration with production ECU stack. "
            "Patent filing in progress for anomaly detection methodology."
        )
    },
    {
        "doc_id": "DOC010",
        "title": "5G Network Slicing Security Architecture for V2X Applications",
        "category": "technical_report",
        "sensitivity": "INTERNAL",
        "date": "2024-12-01",
        "author": "Wireless Infrastructure Team",
        "content": (
            "Technical Report: 5G network slicing security architecture for V2X applications. "
            "Architecture separates safety-critical V2X (URLLC slice, sub-1ms latency) from "
            "infotainment (eMBB) via hardware-enforced slice isolation. Security controls: "
            "per-slice 5G-AKA authentication, IETF QUIC with TLS 1.3, slice boundary monitoring. "
            "Threat model: inter-slice attack surface reduced 89% vs flat network. NIST CSF 2.0 "
            "controls: PR.AA-05, DE.CM-01, RS.MA-02. 3GPP Release 17 compliance verified. "
            "Performance: 99.999% availability for safety slice, 12ms V2X latency, 2.3Gbps eMBB. "
            "Deployment: 3 sites Q2 2025, full network Q4 2025."
        )
    },
]

with open('data/corpus.json', 'w') as f:
    json.dump(documents, f, indent=2)

print(f"Mock document corpus created: {len(documents)} documents")
for doc in documents:
    print(f"  {doc['doc_id']}: [{doc['sensitivity']}] {doc['title'][:60]}...")
