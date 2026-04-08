# ca-domain-alignment-audit

**Identity Domain Model Validation for Microsoft Entra Conditional Access**

By Albert Jee | IAM Consultant \& Former Microsoft FastTrack Architect

\---

## Executive Summary

Most Conditional Access implementations are policy-complete but control-incomplete.

They evaluate identity.

They do not enforce identity boundaries.

This audit engine evaluates your tenant against a single question:

> \\\*\\\*Does your Conditional Access architecture function as an Identity Control Plane — or a policy collection?\\\*\\\*

\---

## Why This Matters Now

For fifteen years, organizations have muddled through with application-centric policy sprawl. It worked (barely) in an era where identity threats moved at human speed. Today, token theft, sophisticated adversary-in-the-middle attacks, and agentic AI operating at machine speed make the old model indefensible. Attackers don't map your apps—they follow your identity. If your Conditional Access policies don't enforce trust boundaries at the identity domain level, a single compromised user account gives them traverse rights across your entire digital estate at scale.

This is an **architectural validation engine**.

Unlike standard configuration exporters or best-practice checklists, this Graph-backed framework evaluates your architecture for domain alignment, assignment debt, and strategic security gaps. It doesn't just list your policies; it scores your maturity as an Identity Control Plane.

\---

## What This Is Not

* Not a policy deployment tool
* Not a best-practice checklist
* Not a configuration exporter

\---

## 📦 Components

### 1️⃣ CA Policy Domain Check

**Script:** `CA-policy-domain-check.ps1`

**Purpose:** Evaluates a **single Conditional Access policy** and determines whether it is:

* ✅ Domain-aligned
* ⚠ Needs review
* ❌ Application-centric

**Outputs:**

* Console summary
* HTML report
* JSON export

**Typical use cases:**

* Reviewing new policies before production
* Architecture validation during audits
* Peer review of privileged access controls

\---

### 2️⃣ CA Tenant Domain Scorecard

**Script:** `CA-tenant-domain-scorecard.ps1`

**Purpose:** Performs a **tenant-wide analysis** of all Conditional Access policies and produces an executive scorecard.

**Outputs:**

* Console scorecard
* HTML executive report
* JSON export
* CSV policy summary

**Identifies:**

* Privileged boundary gaps
* Workload identity coverage gaps
* Break-glass tripwire visibility
* Individual user assignment risks

\---

## Architecture Model

This project implements the **Identity Control Plane model**:

```
Access Request
    ↓
Evaluation Signals
(Identity / Device / Location / Risk / Session)
    ↓
Conditional Access Engine
    ↓
Enforcement Decision
    ↓
Protected Resources
```

**The Shift:**

Stop viewing Conditional Access as a series of gates in front of applications. In a Control Plane model, CA is the centralized logical layer that enforces uniform trust requirements across every identity domain, regardless of the target. If the identity doesn't meet the domain's trust bar, the plane enforces access decisions at token issuance, governing entry to all resources. You're not managing 500 doors—you're enforcing four identity corridors.

**The Identity Control Plane vs. The Ghost Roster:**

In the legacy model, your evaluation signals are white noise—a mess of individual GUIDs and "temporary" exclusions. The Domain-Aligned model replaces this noise with governance. This audit validates that your engine only accepts signals from governed Domain Groups. If an identity doesn't fit a domain, it has no path forward. The audit queries each policy's IncludeUsers and ExcludeUsers properties, flags any GUID that doesn't resolve to a known Domain group, and surfaces these hard-coded backdoors that your current reporting misses.

\---

## 🧠 Domain Model

Policies are evaluated against these identity domains:

|Domain|Description|
|-|-|
|**Privileged**|Tier-0 / admin identities|
|**Workforce**|Employees and standard users|
|**Guest**|B2B / external users|
|**Workload**|Service principals and managed identities|

Classification is based on:

* User \& group targeting
* Application scope
* Authentication strength
* Device trust requirements
* Session controls
* Exclusion hygiene

\---

## The Two Models: Application-Centric vs Domain-Aligned

### The Classic Approach: Application-Centric CA

For fifteen years, most organizations built Conditional Access one application at a time. New SaaS tool launches. You create a policy targeting that specific app. You assign it to users. Deploy. Repeat.

Application-centric CA doesn't scale; it compounds architectural debt. You start with five "standard" policies and end with 127 "temporary" exceptions that have outlasted the admins who wrote them. Each targets different applications. Each has its own user scope, often hard-coded to individual names. Each has grown exceptions over time.

**The structural failures:**

**Identity Sprawl** — App-first sprawl naturally drifts toward individual user assignment. The sprawl begins with a single "emergency" GUID. An admin bypasses the group provisioning process to solve a ticket, creating a permanent backdoor that outlives the contractor it was meant for. Repeat this across five administrators over three years. You are left with a ghost roster of hundreds of hard-coded IDs scattered across your tenant's attack surface, most of whom left the company before the last audit. This is the roster problem — the most common source of ungoverned access in CA architectures.

**Coverage Gaps** — New applications onboard faster than policies are written. Copilot launches. 500 users connect before your security team writes a policy. They sign in without Conditional Access enforcement — not because you allowed it, but because you didn't restrict it yet.

**Privilege Creep** — Your Global Administrators are protected by a CA policy scoped to the Azure portal. It requires MFA and compliant device. But administrators also operate via Microsoft Graph and PowerShell. Those endpoints are different service principals. Portal-scoped policies may not apply to Microsoft Graph or PowerShell endpoints unless those resources are explicitly included in policy scope. An attacker who compromises a Global Administrator and avoids the portal interface faces zero elevated authentication requirement on Graph. Most organizations have protected the portal and forgotten the API.

**Operational Debt** — Every policy is a separate governance decision. User scope, app scope, grant controls, session controls — all four dimensions can have exceptions and exclusions. As your policy count grows, the audit surface grows faster than your team's ability to govern it. I audited a Fortune 500 organization with 127 Conditional Access policies. When asked how many policies explicitly protected the Azure portal (where Global Administrators operate), they couldn't answer without a custom script. The answer: 47 separate policies with different enforcement rules covering the same critical surface.

### The Alternative: Domain-Aligned CA

The domain-aligned model starts with a different question: instead of "what applications do I have?", ask "what classes of actor populate my tenant?"

Most organizations have four types of identity—which we define as **Identity Domains**. In this audit framework, a Domain is a logical grouping enforced via dedicated Security Groups. The Identity Control Plane operates on a fundamental governance requirement: Every identity must reside in exactly one Domain group. If an identity overlaps domains or sits in no-man's-land, the control plane is fractured. This audit evaluates the policy alignment, assuming your group governance is the foundation.

1. **Workforce** — standard employees on corporate devices
2. **Privileged** — administrative identities requiring elevated controls
3. **Guest** — external collaborators with bounded trust
4. **Workload** — service principals and automation identities

Instead of writing policies for applications, write policies for these four containers. Each domain gets one or two policies defining the trust boundary. The Control Plane assumes every resource is critical; therefore, every policy targets the entire digital estate by default. By treating every resource as critical, you eliminate the gap-finding that happens when you forget to protect one API. Every policy targets a security group containing all identities in that domain.

In this model, you don't manage app-specific gates; you manage the trust bar for the identity. If an outlier application truly cannot meet the domain's trust requirement, it is handled as a documented, time-bound exception—not as a reason to lower the bar for the entire estate.

When a new SaaS application launches, you do not write a new policy. Users in the Workforce domain are already covered by Workforce policies. Users in the Privileged domain are already covered by Privileged policies. The application is automatically protected without a single policy change.

\---

## ⚠️ Known Limitations \& Disclaimers

These scripts are tutorial companions to the Medium article series, not enterprise audit tools. Understand these limitations before interpreting findings.

**Break-Glass Accounts \& Conditional Access**

These scripts detect Conditional Access exclusions that may represent intentional break-glass carve-outs (accounts explicitly excluded from CA policies). This script does NOT audit whether you actually have a break-glass account or whether it is properly documented. It only shows CA policy exclusions. Many organizations operate without formal break-glass accounts—that is a separate governance decision, not a CA architecture issue. If you use break-glass: verify it is explicitly excluded from all CA policies. If you do not use break-glass: acknowledge that in your risk assessment.

**Pattern-Based Break-Glass Detection**

Break-glass evidence detection uses pattern-matching against group and user display names (keywords: "break," "glass," "emergency"). If your emergency accounts do not follow these naming conventions, the scripts will not detect them. This is a model limitation, not a regression.

**Graph API Throttling Near Policy Limits**

Microsoft enforces a hard limit of 195 Conditional Access policies per tenant. Tenants approaching or at this limit may experience increased Graph API latency during script execution. The scripts include retry logic for transient throttling (429 responses), but evaluation of very large policy sets can still cause delays. If your tenant is near the 195-policy limit, run audits during off-hours. See Microsoft's Conditional Access scaling guidance for policy consolidation patterns.

**Authentication Strength Detection**

Auth strength detection relies on Microsoft Graph response format. If Graph omits `displayName` in future API versions, the scripts fall back to ID-based detection. Verify auth strength detection accuracy in your specific environment.

**Output Limitations**

These scripts export findings in console output, HTML, JSON, and CSV formats suitable for review and documentation. They are not designed for automated remediation. Security decisions should always involve human review and testing.

\---

## 🚀 Quick Start

### Prerequisites

* PowerShell 7.2+
* Microsoft Graph PowerShell SDK
* Required Graph permissions:

  * `Policy.Read.All`
  * `Group.Read.All`
  * `Directory.Read.All`
  * `User.Read.All` (tenant scorecard only)

### Installation

Clone this repository:

```powershell
git clone https://github.com/albertjee/entra-identity-audit.git
cd entra-identity-audit
```

### 🔍 Analyze a Single Policy

```powershell
.\\\\CA-policy-domain-check.ps1 `
  -PolicyName "CA - Privileged - All Apps"
```

or by PolicyId:

```powershell
.\\\\CA-policy-domain-check.ps1 `
  -PolicyId "11111111-2222-3333-4444-555555555555"
```

### 📊 Analyze the Entire Tenant

```powershell
.\\\\CA-tenant-domain-scorecard.ps1
```

Optional switches:

```powershell
-IncludeReportOnly
-TenantId contoso.onmicrosoft.com
-ExportPath .\\\\Outputs
```

\---

## ✅ Interpreting Results

### What Your Alignment Score Actually Means

**Important Prerequisite:** This audit evaluates policy alignment assuming your group governance is the foundation. The model assumes every identity is governed into a single domain group as a design requirement; enforcement depends on external identity governance processes. If users overlap domains or exist in no-man's-land, the Control Plane is fractured regardless of policy scores. Use this audit to expose policy gaps; use your group management console to enforce the governance structure.

Your domain-aligned score (0-100) reflects your organizational risk posture:

* **Score below 50 (The Roster Trap):** Your security relies on administrator memory. You are managing a "ghost roster" of individual users and one-off app gates. When an admin leaves, their logic stays, and your debt grows.
* **Score 50–79 (The Hybrid Muddle):** You have the "Identity Control Plane" in name only. You use global policies, but your "Exclusion Hygiene" is so poor that your perimeter is more Swiss cheese than shield.
* **Score 80+ (The Identity Control Plane):** You have achieved structural security. You no longer "deploy" security for new apps; they inherit it. You have moved from playing Whac-A-Mole to managing a fortress.

### Policy Classifications Explained

**DOMAIN-ALIGNED** — Targets a security group via IncludeGroups. Uses All Cloud Apps. Enforces appropriate controls for the inferred domain. No individual user GUIDs. This is the target state.

**PARTIALLY-ALIGNED** — Shows some domain structure but has gaps. May use All Cloud Apps with exclusions or have individual user adds. May lack expected controls. Review and resolve before production reliance.

**APPLICATION-CENTRIC** — Scoped to specific applications rather than All Cloud Apps. Often uses individual user assignment. Requires policy updates when new applications onboard. This is the pattern to migrate away from.

**GLOBAL-BASELINE** — Targets All Identities (IncludeUsers: All), All Cloud Apps. Enforces legacy authentication block (block control + exchangeActiveSync/other client app types). Foundational — should exist in every tenant.

**PRIVILEGED-UNGOVERNED** — Targets privileged identities but missing All Cloud Apps scope or missing phishing-resistant authentication (authenticationStrength). Critical gap.

**REPORT-ONLY / DISABLED** — Not enforcing. Does not contribute to effective coverage.

### Numeric Scoring

Policies are scored on impact to domain alignment:

* **+2**: DOMAIN-ALIGNED or GLOBAL-BASELINE — Moves you toward the model
* **+1**: PARTIALLY-ALIGNED — Partial progress
* **0**: APPLICATION-CENTRIC or REPORT-ONLY — No progress
* **-1**: PRIVILEGED-UNGOVERNED — Active gap in critical area

Your scorecard produces an overall Alignment Score (0-100) with verdict:

* **80%+**: DOMAIN-ALIGNED
* **50-79%**: IN TRANSITION
* **Below 50%**: APPLICATION-CENTRIC

### Strategic Gap Findings: The Cost of Inaction

**Privileged Boundary Gap** — Your Tier 0 identities are one token-theft away from total tenant compromise. Without phishing-resistant enforcement on the *All Cloud Apps* scope, your "admin MFA" is a speed bump, not a wall. Gap detected when: No DOMAIN-ALIGNED Privileged policy with All Cloud Apps + authenticationStrength + device control. Penalty: -5 points.

**Workload Identity Gap** — You are securing the front door while the loading dock is wide open. If you aren't auditing service principal CA, you aren't governing your most privileged actors. Service principals are the "invisible workforce." This gap is flagged when the engine detects zero policies targeting `servicePrincipals` via `clientApplications` conditions. In a domain-aligned model, Workload identities require the same centralized logical layer as humans—enforcing credential restrictions and IP pinning across the entire estate, not just for a few "high-value" apps. Penalty: -3 points.

**The Break-Glass Tripwire Gap** — Your safety valve is either blocked or invisible. The audit flags this gap when BOTH conditions are missing: (1) your emergency accounts are accidentally trapped by "All Cloud Apps" policies without a documented exclusion, AND (2) there is no dedicated tripwire policy—a monitoring-only CA policy that fires an alert the moment a break-glass credential is used. If you have exclusion but no tripwire, you have a backdoor with no alarm. If you have a tripwire but accounts are locked out, your safety valve is useless. Both must be present. Penalty: -3 points.

A critical clarification: In a domain-aligned model, break-glass accounts must be **excluded** from Global Baseline or Domain policies to maintain the "Identity Control Plane" during a tenant-wide outage. If a misconfigured global policy locks out break-glass accounts, your safety valve is compromised. The audit flags this gap to ensure that break-glass groups have explicit exclusion rules—or are assigned to a dedicated "Emergency Access" domain with minimal controls.

\---

## Common Findings and What They Mean

**Individual user assignments detected** — Policies contain individual user GUIDs instead of group-based assignments. Consolidate into domain-specific security groups (Workforce-Standard-Users, Tier0-Privileged-Identities) and update policy targets.

**All Cloud Apps policy contains excluded applications** — Policy targets All Cloud Apps but excludes specific applications. Verify each exclusion has a separate covering policy. Remove unjustified exclusions.

**Privileged domain missing authenticationStrength** — Privileged policy uses boolean MFA instead of phishing-resistant (FIDO2/certificate-based). Upgrade to AuthenticationStrength with phishing-resistant definition.

**Break-glass group not explicitly excluded from MFA policy** — Break-glass accounts need sign-in without MFA if Graph is unavailable. Add break-glass group to Exclude Groups on MFA policies. Create separate tripwire policy targeting break-glass to trigger high-priority alerts on any sign-in.

**No service principal Conditional Access policies found** — Implement workload CA policies targeting Service-Principal-Identities group via conditions.clientApplications. Enforce credential and scope restrictions.

\---

## 🔐 Security \& Design Principles

* ✅ No write operations against Microsoft Graph
* ✅ Safe to run in production tenants
* ✅ No tenant data sent externally
* ✅ All reports generated locally
* ✅ Defensive handling of Graph throttling and schema drift

\---

## 📁 Repository Structure

```
.
├── CA-policy-domain-check.ps1
├── CA-tenant-domain-scorecard.ps1
├── SETUP.md
├── RBAC\\\_ROLES\\\_GUIDANCE.md
└── README.md
└── README.md
```

\---

## ⚠️ Limitations

* This tool evaluates **policy design quality**, not runtime enforcement success
* Domain inference relies on naming conventions and targeting patterns
* Authentication strength evaluation depends on Graph schema availability

\---

## 🛣️ Roadmap

Planned improvements include:

* Shared PowerShell module packaging
* PSScriptAnalyzer enforcement
* SARIF output for security tooling
* Azure DevOps pipeline support
* Optional What-If and dry-run modes

\---

## Next Steps

1. **Run CA-tenant-domain-scorecard.ps1** against your tenant. Review the HTML report.
2. **Identify your highest-impact gaps** (PRIVILEGED-UNGOVERNED, large APPLICATION-CENTRIC clusters, individual assignment debt).
3. **Start with privileged domain**. Upgrade to authenticationStrength. Ensure All Cloud Apps scope.
4. **Migrate highest-value APPLICATION-CENTRIC policies** to domain structure.
5. **Consolidate individual user assignments** into security groups.
6. **Document rationale for exclusions**. Remove unjustified ones.
7. **Implement break-glass tripwire** policy (monitoring only, no block).
8. **Re-run the scorecard monthly**. Track progress toward domain alignment.

\---

## About

Albert Jee is an independent IAM consultant and former Microsoft FastTrack Architect with fifteen years of experience designing enterprise identity and access management solutions.

This repository is built for architects and CISOs evaluating whether their Conditional Access architecture scales or staggers. If your tenant is stuck in the application-centric model and you want guidance moving toward domain alignment — or if you are building a new tenant and want to start right — reach out.

**linkedin.com/in/albertjee**

**github.com/albertjee**

\---

*This repository contains audit and evaluation scripts only. Nothing in these scripts modifies tenant state. Use in read-only audit mode. Test in non-production environments first.*

