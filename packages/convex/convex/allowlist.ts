import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { normalizeEmail } from "../src/index";

export const allow = mutation({
  args: { email: v.string(), note: v.optional(v.string()), addedBy: v.optional(v.string()) },
  handler: async (ctx, args) => {
    const email = normalizeEmail(args.email);
    const existing = await ctx.db
      .query("allowed_users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .first();

    if (existing) {
      return { status: "exists", email } as const;
    }

    await ctx.db.insert("allowed_users", {
      email,
      note: args.note,
      addedBy: args.addedBy,
      addedAt: Date.now()
    });

    return { status: "added", email } as const;
  }
});

export const remove = mutation({
  args: { email: v.string() },
  handler: async (ctx, args) => {
    const email = normalizeEmail(args.email);
    const existing = await ctx.db
      .query("allowed_users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .first();

    if (!existing) {
      return { status: "missing", email } as const;
    }

    await ctx.db.delete(existing._id);
    return { status: "removed", email } as const;
  }
});

export const list = query({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query("allowed_users").collect();
    return rows
      .map((row) => ({
        email: row.email,
        addedBy: row.addedBy,
        note: row.note,
        addedAt: row.addedAt
      }))
      .sort((a, b) => a.email.localeCompare(b.email));
  }
});

export const isAllowed = query({
  args: { email: v.string() },
  handler: async (ctx, args) => {
    const email = normalizeEmail(args.email);
    const row = await ctx.db
      .query("allowed_users")
      .withIndex("by_email", (q) => q.eq("email", email))
      .first();
    return { email, allowed: Boolean(row) } as const;
  }
});
