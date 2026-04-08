# RBAC Roles Required to Run ca-domain-alignment-audit Scripts

## Quick Answer

**Minimum role:** Security Reader — If you can't run this audit with Security Reader, your design is already over-privileged.

**Recommended role:** Security Administrator (for SOC/security team integration)

**Not sufficient:** Directory Reader, Conditional Access Administrator alone, or Reader

---

## Detailed RBAC Matrix

| Azure AD Role | Can Run Scripts | Graph Scopes Needed | Notes |
|---|---|---|---|
| **Global Administrator** | Yes — Full | All scopes implicit | Overkill but works. Highest privilege, not recommended for routine audits. |
| **Security Administrator** | Yes — Full | Policy.Read.All, Group.Read.All, Directory.Read.All, AuditLog.Read.All, User.Read.All | Best practice. Full SOC authority. Can also remediate findings in other tools. |
| **Security Reader** | Yes — Full | Policy.Read.All, Group.Read.All, Directory.Read.All, AuditLog.Read.All, User.Read.All | Minimum sufficient. Read-only. No remediation authority. Best for audit-only scenarios. |
| **Conditional Access Administrator** | Partial — Limited | Policy.Read.All only | Can read policies but lacks directory and identity read permissions. Not recommended as a standalone audit role due to incomplete directory and identity visibility. |
| **Directory Reader** | No — Insufficient | Directory.Read.All only | Missing Policy.Read.All. Scripts will fail or return incomplete results during policy enumeration. |
| **Reader** | No — Insufficient | Minimal graph scopes | Too restrictive. Will fail on all Graph operations. |

---

## Script-Specific Permission Requirements

### CA-policy-domain-check.ps1 (Single policy evaluation)

**Required scopes:**
- `Policy.Read.All` — Enumerate and retrieve individual CA policies
- `Group.Read.All` — Resolve group IDs to display names (for User Scope criterion)
- `Directory.Read.All` — Resolve directory objects if policy contains role targeting

**Why each matters:**
- Without Policy.Read.All: Cannot retrieve the policy to evaluate
- Without Group.Read.All: Group IDs appear as GUIDs in criterion results instead of names (unusable)
- Without Directory.Read.All: Cannot infer domain from role assignments in policy

**Minimum role that satisfies all:** Security Reader

---

### CA-tenant-domain-scorecard.ps1 (Tenant-wide scoring)

**Required scopes:**
- `Policy.Read.All` — Enumerate all CA policies in tenant
- `Group.Read.All` — Resolve all group IDs in all policies to names (required for classification)
- `Directory.Read.All` — Resolve directory objects for mixed-type assignments
- `User.Read.All` — Resolve individual user GUIDs to display names + UPN (for assignment debt reporting)
- `AuditLog.Read.All` — Not required for current script execution, but included for forward compatibility with telemetry correlation features

**Why each matters:**
- Without Policy.Read.All: Cannot enumerate policies
- Without Group.Read.All: Policy classification becomes unreliable (cannot infer domain from group names)
- Without Directory.Read.All: Mixed-type assignment resolution fails
- Without User.Read.All: Individual assignment debt report shows GUIDs instead of names (unusable for remediation)
- AuditLog.Read.All: Included in prerequisites for future versions

**Minimum role that satisfies all:** Security Reader

---

## Azure AD Role Comparisons

### Security Reader (Recommended for routine audits)

**Includes these permissions:**
- Read all security alerts, secure score, audit logs, risk events
- Read Conditional Access policies, named locations, identity protection policies
- Read groups and group memberships
- Read user properties and directory information

**Advantage:** Minimal privilege principle. Audit-only authority. No risk of accidental changes.

**Disadvantage:** Cannot act on findings (no remediation authority). Requires Security Administrator or Global Administrator to implement fixes.

**Best for:** Scheduled audits, SOC review cycles, third-party consultants, compliance reviews.

---

### Security Administrator (Recommended for integrated security teams)

**Includes Security Reader permissions PLUS:**
- Manage Conditional Access policies (create, update, delete)
- Manage authentication methods
- Reset user passwords
- Manage security alerts and incidents

**Advantage:** Can both audit and remediate. Full SOC integration. Can implement findings immediately.

**Disadvantage:** Higher privilege. Requires more careful access governance.

**Best for:** Active security teams that audit and remediate simultaneously. Security operations centers.

---

### Conditional Access Administrator (Not recommended — insufficient for audit-quality analysis)

**Includes only:**
- Manage Conditional Access policies (CRUD operations)
- Read sign-in logs

**Why it's insufficient:**
- No Group.Read.All: Cannot resolve group names. Classification becomes unreliable.
- No User.Read.All: Cannot resolve individual user assignments. Reports will show GUIDs.
- No Directory.Read.All: Cannot resolve directory objects.

Conditional Access Administrator provides sufficient access to enumerate policies, but lacks the directory and identity read permissions required for full reporting fidelity. Outputs may be incomplete or contain unresolved object references, making it unsuitable as a standalone role for audit-quality analysis.

**If this is the only role available:** Combine with Directory Reader role (stack permissions via role assignment).

---

## Custom Role Approach (If standard roles are too broad)

If your organization requires least-privilege custom roles, create a custom role with these permissions:

**Custom "CA Auditor" role:**
- `microsoft.directory/conditionalAccessPolicies/read`
- `microsoft.directory/groups/read`
- `microsoft.directory/directoryObjects/read`
- `microsoft.directory/users/read`
- `microsoft.directory/auditLogs/read`

**Assignment:** Assign to users who need to run these scripts only.

**Advantage:** Minimal permissions. Cannot create, update, or delete any resources.

**Disadvantage:** Requires custom role creation (tenant admin work). Not portable across tenants.

---

## Azure AD Global Administrator

**Can the scripts run?** Yes.

**Should they?** No.

Global Administrator is the highest privilege in the tenant. Using GA credentials for routine audits violates least-privilege principle. If your audit requires Global Admin, the audit isn't your problem — your architecture is. Reserve GA for emergency access only.

---

---

## RBAC Configuration Risk

RBAC misconfiguration in audit tooling does not fail loudly — it fails silently. The result is not an error, but a false sense of coverage. In identity architecture, incomplete visibility is more dangerous than no visibility.

---

## Tenant Configuration Considerations

### Admin Units (Role-Scoped Administration)

If your organization uses Entra ID Admin Units to limit scope of role assignments: Audit scripts will enumerate tenant-wide Conditional Access policies, but identity and group resolution will be limited to objects within the Admin Unit scope. For full tenant-wide coverage, request assignment at the root tenant level or temporary elevation.

### Just-In-Time (PAM) Role Elevation

If roles are provided through Privileged Identity Management (Microsoft Entra PIM, Okta Identity Governance, etc.): Request eligible assignment to Security Reader or Security Administrator, activate for audit duration (typically 4-8 hours), and assignment will automatically expire. Activation triggers approval and logging.

---

## Practical Recommendations by Scenario

### Scenario 1: Security Operations Center (SOC) Audit

**Recommended role:** Security Administrator (one per SOC team member running audits)

**Why:** Can audit and coordinate remediation in same workflow. Standard SOC authority level.

**Frequency:** Monthly or quarterly.

---

### Scenario 2: Third-Party Consultant/Auditor

**Recommended role:** Security Reader (time-limited, temporary assignment)

**Why:** Minimal privilege. No risk of consultant making changes. Clear audit trail.

**Frequency:** One-time or annual assessment.

---

### Scenario 3: Compliance/Internal Audit

**Recommended role:** Security Reader (standing assignment)

**Why:** Audit-only authority. Evidence of independence (no remediation capability).

**Frequency:** Quarterly or annual.

---

### Scenario 4: Automated/Scheduled Audits

**Recommended approach:** Service Principal with custom role (CA Auditor equivalent)

**Why:** Automation requires non-interactive account. Custom role minimizes permissions.

**Setup:** Create service principal, assign custom "CA Auditor" role, configure unattended script execution.

---

## Permissions Checklist

Before running these scripts, confirm your user account or service principal has:

- [ ] Policy.Read.All scope
- [ ] Group.Read.All scope
- [ ] Directory.Read.All scope
- [ ] User.Read.All scope
- [ ] AuditLog.Read.All scope (optional, for future versions)

**Test permission:**

```powershell
# Run this to verify your scopes are granted
$context = Get-MgContext
Write-Host "Current scopes:" $context.Scopes -ForegroundColor Green
```

If any required scope is missing, the script will prompt for re-authentication with full scope request.

---

## Related Resources

- SETUP.md — Installation and Graph connection steps
- ca-domain-alignment-audit README — Architecture and audit methodology

---

*Last updated: April 2026 | Companion to SETUP.md and ca-domain-alignment-audit*

## Troubleshooting Insufficient Permissions

**Symptom:** "Insufficient privileges to complete the operation" error during policy enumeration

**Cause:** Missing Policy.Read.All scope

**Fix:** Have tenant admin assign Security Reader role or add Policy.Read.All to custom role

---

**Symptom:** Scripts run but fail or return incomplete results during policy enumeration

**Cause:** Missing Policy.Read.All scope

**Fix:** Verify role assignment includes Policy.Read.All. Request elevation if needed.

**Symptom:** Policy evaluation completes but shows GUIDs instead of group/user names in results

**Cause:** Missing Group.Read.All or User.Read.All scope

**Fix:** If your report shows GUIDs, you don't have an audit — you have noise. Verify all scopes listed above are granted. Re-authenticate if needed.

---

**Symptom:** Scripts run successfully but domain classification is "Unknown" for all policies

**Cause:** Missing Directory.Read.All or Group.Read.All

**Fix:** Confirm scopes are granted and scope list hasn't been cached. Try: `Disconnect-MgGraph; Connect-MgGraph -Scopes "Policy.Read.All","Group.Read.All","Directory.Read.All","User.Read.All"`

