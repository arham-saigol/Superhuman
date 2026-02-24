import type { QueryCtx, MutationCtx } from "./_generated/server";
import { ConvexError } from "convex/values";
import { normalizeEmail } from "../src/index";

export type Authed = {
  email: string;
};

type Ctx = QueryCtx | MutationCtx;

export async function requireIdentity(ctx: Ctx): Promise<Authed> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity?.email) {
    throw new ConvexError("Unauthorized");
  }

  return { email: normalizeEmail(identity.email) };
}

export async function requireActiveUser(ctx: Ctx) {
  const authed = await requireIdentity(ctx);
  const user = await ctx.db
    .query("users")
    .withIndex("by_email", (q) => q.eq("email", authed.email))
    .first();

  if (!user || user.status !== "active") {
    throw new ConvexError("Access not granted");
  }

  return { authed, user };
}

export async function isAllowlisted(ctx: Ctx, email: string): Promise<boolean> {
  const row = await ctx.db
    .query("allowed_users")
    .withIndex("by_email", (q) => q.eq("email", normalizeEmail(email)))
    .first();
  return Boolean(row);
}
