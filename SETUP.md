# Installation & Setup Guide

## Required PowerShell Modules

Your system needs five Microsoft Graph modules. All versions listed are minimum required; higher versions are compatible. Each module provides specific functionality needed by the audit scripts.

While minor version upgrades are typically compatible, major version changes (e.g., v2.x to v3.x) may introduce breaking changes. If you encounter compatibility issues after an update, you can pin a specific version by running: `Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.0.0 -Scope CurrentUser -Force`. Otherwise, allow automatic minor version upgrades.

**Microsoft.Graph.Authentication** — Authenticates to Microsoft Graph and manages access tokens for all API calls.

**Microsoft.Graph.Identity.SignIns** — Provides sign-in logs and identity risk signals used in Conditional Access evaluation.

**Microsoft.Graph.Groups** — Enumerates security groups and group membership for domain classification.

**Microsoft.Graph.Users** — Resolves user objects to display names and UPNs for assignment debt reporting.

**Microsoft.Graph.DirectoryObjects** — Resolves mixed-type assignments and orphan detection.

| Module Name | Minimum Version | Installation Command |
|---|---|---|
| Microsoft.Graph.Authentication | 2.0.0+ | `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force` |
| Microsoft.Graph.Identity.SignIns | 2.0.0+ | `Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force` |
| Microsoft.Graph.Groups | 2.0.0+ | `Install-Module Microsoft.Graph.Groups -Scope CurrentUser -Force` |
| Microsoft.Graph.Users | 2.0.0+ | `Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force` |
| Microsoft.Graph.DirectoryObjects | 2.0.0+ | `Install-Module Microsoft.Graph.DirectoryObjects -Scope CurrentUser -Force` |

## Required Graph Permissions (Scopes)

When the scripts connect to Microsoft Graph, they request the following scopes. Your user account must have consent to these permissions, or Graph will prompt for approval.

| Scope | Purpose |
|---|---|
| `Policy.Read.All` | Read all Conditional Access policies in the tenant. |
| `Group.Read.All` | Enumerate security groups and group membership. |
| `Directory.Read.All` | Read directory objects and organizational information. |
| `User.Read.All` | Read user properties including display name and user principal name. |

## Required Azure AD Roles

Your audit fidelity is bounded by your role — insufficient RBAC equals incomplete truth. You need one of the following Azure AD roles to run these scripts. The minimum role is **Security Reader**. Security Reader is sufficient in most audit-only scenarios, subject to tenant configuration and licensing constraints. Security Administrator is recommended only if the operator intends to remediate findings in-session.

| Azure AD Role | Can Run Scripts | Graph Scopes Needed | Best For |
|---|---|---|---|
| **Security Administrator** | Yes — Full | All listed above | Active security teams that audit and remediate simultaneously |
| **Security Reader** | Yes — Full | All listed above | Audit-only scenarios; third-party consultants; compliance reviews |
| **Conditional Access Administrator** | Partial — Limited | Can read policies but lacks sufficient directory read permissions to fully resolve user, group, and assignment context | Not recommended — cannot resolve group/user names |
| **Global Administrator** | Yes — Full | All implicit | Break-glass control only — not an operating role due to least-privilege considerations |
| **Directory Reader** | No — Insufficient | Missing Policy.Read.All | Will fail on policy enumeration |

Security Reader is sufficient for audit-only scenarios. For custom roles, detailed scenario comparisons, remediation workflows, and troubleshooting guidance, see [RBAC_ROLES_GUIDANCE.md](./RBAC_ROLES_GUIDANCE.md).

## Pre-Flight Validation and Environment Setup

Access to Microsoft Graph is governed by three independent controls: role assignment, consented scopes, and tenant-level restrictions. Validation must confirm all three — not just token issuance.

**1. Verify your Azure AD role:**

Before installing modules, confirm you have Security Reader or higher role assignment in your tenant. If unsure, contact your tenant administrator. If you don't have the required role, request the assignment before proceeding to Step 2.

**2. Set Execution Policy and install required modules:**

Ensure your system allows script execution, then install the modules:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Groups -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force
Install-Module Microsoft.Graph.DirectoryObjects -Scope CurrentUser -Force
```

Only apply Set-ExecutionPolicy if permitted by your organization's security policy.

If the Set-ExecutionPolicy command fails, your organization may enforce execution policy via Group Policy. Contact your administrator rather than attempting to override locally.

The `-Force` flag bypasses confirmation prompts. In restricted environments, remove this flag from all five `Install-Module` commands and answer prompts manually, or use `-SkipPublisherCheck` to bypass NuGet provider issues while maintaining security.

**3. Verify installation:**

```powershell
Get-Module Microsoft.Graph.* -ListAvailable | Select-Object Name, Version
```

**4. Audit your Graph session:**

Graph authentication is not trust — verify the session before trusting the data. Confirm your session context and ensure all four required scopes are present, then validate effective access through successful Graph queries:

```powershell
Connect-MgGraph -Scopes Policy.Read.All, Group.Read.All, Directory.Read.All, User.Read.All
(Get-MgContext).Scopes
```

If scopes appear missing or stale, disconnect and reconnect to force a fresh consent and token issuance:

```powershell
Disconnect-MgGraph
Connect-MgGraph -Scopes Policy.Read.All, Group.Read.All, Directory.Read.All, User.Read.All
(Get-MgContext).Scopes
```

If you have multiple tenants, specify the tenant ID in the connection command (replace the command above with):

```powershell
Connect-MgGraph -TenantId <your-tenant-id> -Scopes Policy.Read.All, Group.Read.All, Directory.Read.All, User.Read.All
(Get-MgContext).Scopes
```

If any scope is missing, contact your tenant administrator to approve the following scopes: Policy.Read.All, Group.Read.All, Directory.Read.All, User.Read.All. In some organizations, consent requests are handled through a privileged access management (PAM) process.

**5. Clone the repository:**

Verify Git is installed by running `git --version`. If the command fails, ensure Git is installed and available in your system PATH before proceeding. Then pull the source:

```powershell
git clone https://github.com/albertjee/ca-domain-alignment-audit.git
cd ca-domain-alignment-audit
```

**6. Execute the audit scripts:**

Run the scripts directly from the repository root:

```powershell
.\CA-policy-domain-check.ps1
.\CA-tenant-domain-scorecard.ps1
```

Ensure scripts are reviewed and trusted according to your organization's code execution policies before running.

---

*For more information, see the main README.md.*
