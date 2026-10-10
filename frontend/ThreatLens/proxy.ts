import { clerkMiddleware } from "@clerk/nextjs/server";
import { NextResponse, type NextFetchEvent, type NextRequest } from "next/server";

const configuredClerkMiddleware = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
  ? clerkMiddleware()
  : null;

// Establishes Clerk request context without protecting the public demo pages.
// Individual protected Route Handlers perform their own auth checks.
export default function proxy(request: NextRequest, event: NextFetchEvent) {
  if (!configuredClerkMiddleware) {
    return NextResponse.next();
  }

  return configuredClerkMiddleware(request, event);
}

export const config = {
  matcher: ["/((?!_next|.*\\..*).*)"],
};
