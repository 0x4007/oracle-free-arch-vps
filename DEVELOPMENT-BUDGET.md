# Owner-authorized Oracle development budget

Owner authorization: 2026-09-07.

Oracle provided a USD 300 trial promotion to develop and test this backup and
recovery system. The owner authorizes responsible use of the full USD 300 during
active development. Temporary additional VPS instances, disks, services and
concurrent test environments are permitted when they accelerate useful development
or establish real recovery evidence. Do not block this work solely because its
temporary footprint exceeds Always Free, and do not repeatedly ask the owner to
reconfirm this general spending authorization.

This is one shared cumulative budget, not USD 300 per agent, test, resource or
session. Before spending, reconcile other development resources and reported
usage, estimate the proposed cost and duration, and verify active trial coverage.
Use a bounded test budget and lifetime, track resource ownership and exact IDs,
monitor progress and costs, and clean up temporary resources after their approved
use. Concurrent workloads are permitted; keep OCI mutations coordinated under one
live infrastructure writer. Budget availability is not a reason to waste credit.

Oracle's Organizations API, checked on 2026-09-07, showed an ACTIVE USD 300
promotion, FREE_AND_TRIAL / FREE_TRIAL account representation, and subscription
end date 2026-09-29T23:59:59.999Z. Recheck the actual expiry and current coverage
before new work. The promotion's original amount is not a live remaining-credit
balance, and reported usage can lag. Never assume the credit renews. Never upgrade
to Pay As You Go or incur charges beyond available authorized trial funding.

This authorization supersedes earlier blanket refusals of trial-funded parallel
development and restore drills. It does not remove exact resource and destructive
approval gates, authorize production downtime, permit deletion of good backups,
allow private decryption keys on the source VPS, or authorize backup payload
transfers through the home network. Keep production online; transfer archives
directly between cloud hosts and Backblaze. The Pi holds the operational recovery
kit and orchestrates; it does not relay system archives. Preserve the independent
spare recovery kit.

## Intended normal state after development

Normal operation must remain within the current verified Oracle Always Free
allowances, without depending on trial credits: one production Oracle VPS with
its staging boot and Arch root disks, plus the accepted online Oracle recovery
unit and safe rotation headroom. The recorded production configuration is 2 OCPUs,
12 GB RAM, and 50 GB boot plus 150 GB root storage; verify current provider terms
and tenancy-wide totals rather than treating these values as permanent policy.

The Oracle recovery unit is an online volume-group backup protecting **both**
disks, not one custom image. A custom image does not include an attached root/data
volume and is not assumed to be free. Do not promise instant regeneration or
guaranteed replacement capacity without evidence. Oracle is the first recovery
option; the encrypted independent Backblaze generations are the fallback.

Trial-funded development acceptance, archive verification, boot restoration,
application acceptance, and lasting Free Tier operation are separate claims.
PROJECT-VISION.md remains the owner-controlled charter and is not edited by this
budget note. The owner's explicit development-budget authorization governs the
temporary spending exception; it does not weaken the normal-operation outcome.
