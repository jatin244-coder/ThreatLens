# ThreatLens Phase 8 authentication boundary

This document describes the optional Clerk adapter, not the local integrated
scan path. The local frontend uses the canonical FastAPI backend with explicit
authorization confirmation; it does not claim that Clerk identity is enforced
by that backend yet.

ThreatLens has a Clerk authentication integration boundary for the Next.js App
Router. Public pages remain accessible. The separate Next.js adapter remains
fail-closed and is not used by the local live scan form until the backend has a
compatible authentication and ownership-verification contract.

## Required environment configuration

Configure these values in the deployment secret manager and local `.env.local` without committing them:

```text
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=<Clerk publishable key>
CLERK_SECRET_KEY=<Clerk secret key>
```

The publishable key is client-visible. `CLERK_SECRET_KEY` is server-only and must never be exposed in client code, logs, or reports. Configure the Clerk development instance for email/password sign-in only; social providers and organizations are intentionally not part of this milestone.

For a UI-only local preview, both Clerk variables may be omitted. In that mode,
the root layout and request proxy skip Clerk initialization, and the sign-in and
sign-up routes show a setup notice instead of simulating authentication. The
protected API routes remain fail-closed and continue returning `401` because no
trusted Clerk identity is available.

## Trust boundary

`clerkAuthenticationProvider` calls Clerk's server-side `auth()` helper. It maps only the verified `userId` claim to the application principal. Request-body identity fields, authorization checkboxes, and client-provided account IDs are ignored. The provisional `accountId` equals the verified user ID until a future internal account store exists.

The Clerk middleware establishes request context but does not protect public pages. Protected Route Handlers must continue to call `requireAuthenticatedPrincipal` themselves.

## Production security note

Mandatory MFA is deferred for ordinary users. Before production use, ThreatLens should assess MFA requirements for administrators, support staff, domain ownership changes, and other high-impact actions. Session lifetime, revocation, account recovery, email verification, rate limits, bot protection, and audit logging must also be configured and tested.

## Not implemented

- Domain ownership verification
- Internal account persistence
- Scan-job persistence or queueing
- Worker infrastructure
- Outbound requests or live scanning
- Organization accounts or social login
