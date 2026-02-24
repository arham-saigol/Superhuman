import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { normalizeEmail } from "../src/index";
import { requireIdentity, requireActiveUser, isAllowlisted } from "./auth";

export const accessStatus = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity?.email) {
      return { authenticated: false, allowlisted: false, activeProfile: false, email: null } as const;
    }

    const email = normalizeEmail(identity.email);
    const allowlisted = await isAllowlisted(ctx, email);
    const profile = await ctx.db
      .query("users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .first();

    return {
      authenticated: true,
      allowlisted,
      activeProfile: profile?.status === "active",
      email
    } as const;
  }
});

export const activateIfAllowlisted = mutation({
  args: {},
  handler: async (ctx) => {
    const { email } = await requireIdentity(ctx);
    const allowlisted = await isAllowlisted(ctx, email);

    if (!allowlisted) {
      return { activated: false, reason: "not_allowlisted" } as const;
    }

    const existing = await ctx.db
      .query("users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .first();

    if (!existing) {
      await ctx.db.insert("users", {
        email,
        status: "active",
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
      return { activated: true, created: true } as const;
    }

    if (existing.status !== "active") {
      await ctx.db.patch(existing._id, {
        status: "active",
        updatedAt: Date.now()
      });
    }

    return { activated: true, created: false } as const;
  }
});

export const me = query({
  args: {},
  handler: async (ctx) => {
    const { authed, user } = await requireActiveUser(ctx);
    return {
      id: user._id,
      email: authed.email,
      status: user.status
    };
  }
});

export const deactivateByEmail = mutation({
  args: { email: v.string() },
  handler: async (ctx, args) => {
    const email = normalizeEmail(args.email);
    const existing = await ctx.db
      .query("users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .first();

    if (!existing) {
      return { status: "missing", email } as const;
    }

    await ctx.db.patch(existing._id, {
      status: "inactive",
      updatedAt: Date.now()
    });

    return { status: "deactivated", email } as const;
  }
});
