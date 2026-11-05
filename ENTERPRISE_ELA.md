# ENTERPRISE SOFTWARE LICENSE AGREEMENT (ELA)
**Single-Tenant Private VPC & Air-Gapped Distribution**

**Effective Date:** Upon Execution of Order Form  
**Licensor:** RitualDev Studio (OPC) Private Limited ("RitualDev"), a corporate software development laboratory organized under the laws of the Republic of India.  
**Contact:** `enterprise@ritualdev.in` | `legal@ritualdev.in` | `security@ritualdev.in`  

---

## 1. Scope & Grant of License

### 1.1 Single-Tenant Private VPC License
Subject to the terms and conditions of this Agreement and payment of the applicable Annual VPC License Fee specified in an executed Order Form, RitualDev grants to Customer a non-exclusive, non-transferable, non-sublicensable worldwide license during the Subscription Term to deploy, configure, and execute the **RitualDev Enterprise Governance Suite** within Customer's private cloud environments (Amazon Web Services VPC, Microsoft Azure VNet, Google Cloud Platform VPC, or on-premises air-gapped bare-metal Kubernetes clusters).

### 1.2 Licensed Components
The Enterprise Governance Suite comprises:
1. **AgentShield Policy Controller**: Real-time operating system kernel containment, eBPF syscall filtering, and canary surrogate replacement engine (`AGENTSHIELD_AIR_GAPPED=1`).
2. **DBShield Wire Protocol Proxy**: Sub-millisecond PostgreSQL Frontend/Backend Protocol 3.0 and MySQL packet interception proxy, ephemeral copy-on-write DuckDB/SQLite shadow databases, and wire-level HMAC-SHA256 PII masking.
3. **SkillPrism Distributed Control Hub**: Reciprocal Rank Fusion (RRF) on-device vector discovery, hierarchical two-tier cache (L1 in-memory + L2 clustered VPC Redis), and bidirectional taint tracking.
4. **Infrastructure-as-Code (IaC) Automation**: Modular Terraform / OpenTofu modules, Helm charts, and automated container image tarballs.

---

## 2. Commercial Pricing Tiers

The annual subscription fee is billed per deployed VPC / Virtual Network instance:

| License Tier | Annual Fee (USD) | Maximum Agents / Nodes | High-Availability Redis | Ephemeral Shadow DBs | Deployment Engineering Support | Guaranteed SLA |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Standard Enterprise VPC** | **$35,000 / yr / VPC** | Up to 100 Agent Seats / 25 Pods | Clustered Multi-AZ | Up to 50 Concurrent Shadows | Turnkey Onboarding (< 4 hrs) | 99.9% Uptime (P1 < 2 hrs) |
| **Advanced High-Throughput VPC** | **$55,000 / yr / VPC** | Up to 500 Agent Seats / 100 Pods | Multi-Region Active/Active | Unlimited Ephemeral Shadows | Dedicated Forward-Deployed Architect | 99.95% Uptime (P1 < 1 hr) |
| **Mission-Critical Air-Gapped VPC** | **$75,000 / yr / VPC** | Unlimited Agent Fleet | Air-Gapped Self-Contained Mesh | Unlimited Ephemeral + Zero-Network | On-Site / White-Glove Security Team | 99.99% Uptime (P1 < 30 mins, 24/7) |

*Multi-VPC discounts apply for customers deploying 3 or more VPC instances (15% across all stacks).*

---

## 3. Deployment, Delivery & Air-Gapped Packaging

### 3.1 Turnkey Rollout Guarantee (< 2 Hours)
RitualDev guarantees that using the provided Terraform / OpenTofu modules and Helm charts, Customer's internal platform engineering team can achieve an operational, hardened single-tenant control plane deployment within less than two (2) hours from receiving the distribution bundle.

### 3.2 Air-Gapped Self-Contained Binaries
In environments where `AGENTSHIELD_AIR_GAPPED=1` is enforced:
- Zero outbound telemetry, usage phone-home, or third-party API dependencies exist.
- All Docker container images are supplied via cryptographic tarballs signed with Cosign / Sigstore.
- Embedding weights (FastText / MiniLM) and BM25 tokenizers run strictly on-device without external model calls.

---

## 4. Maintenance, Security Patches & Software Updates

### 4.1 Automated Patch Delivery
RitualDev continuously provides:
- Monthly maintenance releases delivering zero-overhead performance optimizations and upstream Kubernetes / Cloud SDK compatibility.
- Critical zero-day vulnerability security patches within twenty-four (24) hours of triage under RFC 9116 statutory disclosure rules.

### 4.2 Local Patch Application
Patches for air-gapped instances are delivered via offline diff bundles and signed container registries, ensuring Customer maintains 100% control over deployment timing.

---

## 5. Enterprise Service Level Agreement (SLA)

| Severity Level | Definition | Initial Response Time | Resolution Objective |
| :--- | :--- | :--- | :--- |
| **P1 - Critical** | Catastrophic control plane outage, wire proxy failure blocking production workloads. | **< 30 minutes** (Air-Gapped Tier) / **< 1 hour** (Standard) | Workaround or hotfix within 6 hours. Continuous 24/7 engagement. |
| **P2 - High** | Significant degradation in tool discovery latency or shadow DB execution; no data loss. | **< 2 hours** | Patch or mitigation within 24 hours. |
| **P3 - Normal** | Configuration inquiries, minor bugs, feature enhancements. | **< 8 business hours** | Scheduled next patch cycle. |

---

## 6. Zero Data Retention & Statutory Compliance Warranty

### 6.1 Zero Data Retention
RitualDev expressly represents and warrants that the Software operates exclusively on Customer's infrastructure. No Customer database queries, prompt tokens, code embeddings, tool payloads, or system metadata are ever transmitted to, stored on, or accessible by RitualDev or any third-party infrastructure.

### 6.2 Compliance par Excellence
The Software enables Customer to maintain continuous compliance with:
- **NIST SP 800-218** (Secure Software Development Framework)
- **SOC 2 Type II** Trust Services Criteria (Security, Confidentiality, Processing Integrity)
- **ISO/IEC 27001:2022** Controls
- **EU General Data Protection Regulation (GDPR)** (Art. 28 Processor obligations)
- **India Digital Personal Data Protection Act, 2023 (DPDP Act)**

---

## 7. Term and Termination

1. **Term**: The Agreement takes effect on the Order Form Effective Date and remains active for one (1) calendar year, renewing automatically unless written notice is given thirty (30) days prior to expiration.
2. **Post-Termination**: Upon termination, Customer may retain archived audit logs generated by the Software, but must cease active execution of the wire proxy and control plane.

---

## 8. Governing Law and Dispute Resolution

This Agreement shall be governed by and construed in accordance with the laws of India, without regard to conflict of law principles. Any dispute arising out of or in connection with this Agreement shall be settled by arbitration in New Delhi in accordance with the Arbitration and Conciliation Act, 1996.

---

**For Enterprise Procurement, Custom Order Forms & Legal Review:**  
Email: `enterprise@ritualdev.in` | Security: `security@ritualdev.in`  
Corporate Gateway: [https://ritualdev.in](https://ritualdev.in)
