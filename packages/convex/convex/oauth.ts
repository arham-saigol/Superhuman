import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

const SYSTEM_SUBJECT = "system";

export const upsertProviderTokens = mutation({
  args: {
    provider: v.string(),
    accessTokenEncrypted: v.string(),
    refreshTokenEncrypted: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    accountEmail: v.optional(v.string()),
    tokenType: v.optional(v.string()),
    scope: v.optional(v.string()),
    subject: v.optional(v.string())
  },
  handler: async (ctx, args) => {
    const subject = args.subject?.trim() || SYSTEM_SUBJECT;
    const existing = await ctx.db
      .query("oauth_tokens_encrypted")
      .withIndex("by_provider", (q) => q.eq("provider", args.provider))
      .collect();

    const current = existing.find((row) => (row.subject ?? SYSTEM_SUBJECT) === subject);
    const now = Date.now();

    if (current) {
      await ctx.db.patch(current._id, {
        accessTokenEncrypted: args.accessTokenEncrypted,
        refreshTokenEncrypted: args.refreshTokenEncrypted,
        expiresAt: args.expiresAt,
        accountEmail: args.accountEmail,
        tokenType: args.tokenType,
        scope: args.scope,
        subject,
        updatedAt: now
      });
      return { status: "updated", provider: args.provider, subject } as const;
    }

    await ctx.db.insert("oauth_tokens_encrypted", {
      provider: args.provider,
      subject,
      accessTokenEncrypted: args.accessTokenEncrypted,
      refreshTokenEncrypted: args.refreshTokenEncrypted,
      expiresAt: args.expiresAt,
      accountEmail: args.accountEmail,
      tokenType: args.tokenType,
      scope: args.scope,
      createdAt: now,
      updatedAt: now
    });
    return { status: "created", provider: args.provider, subject } as const;
  }
});

export const providerStatus = query({
  args: {
    provider: v.string(),
    subject: v.optional(v.string())
  },
  handler: async (ctx, args) => {
    const subject = args.subject?.trim() || SYSTEM_SUBJECT;
    const rows = await ctx.db
      .query("oauth_tokens_encrypted")
      .withIndex("by_provider", (q) => q.eq("provider", args.provider))
      .collect();
    const tokenRow = rows.find((row) => (row.subject ?? SYSTEM_SUBJECT) === subject);

    if (!tokenRow) {
      return {
        provider: args.provider,
        subject,
        authorized: false,
        hasRefreshToken: false,
        updatedAt: null,
        expiresAt: null,
        accountEmail: null
      } as const;
    }

    return {
      provider: args.provider,
      subject,
      authorized: true,
      hasRefreshToken: Boolean(tokenRow.refreshTokenEncrypted),
      updatedAt: tokenRow.updatedAt,
      expiresAt: tokenRow.expiresAt ?? null,
      accountEmail: tokenRow.accountEmail ?? null
    } as const;
  }
});

export const listProviderStatus = query({
  args: {
    subject: v.optional(v.string())
  },
  handler: async (ctx, args) => {
    const subject = args.subject?.trim() || SYSTEM_SUBJECT;
    const rows = await ctx.db.query("oauth_tokens_encrypted").collect();

    const byProvider = new Map<
      string,
      {
        provider: string;
        subject: string;
        authorized: boolean;
        hasRefreshToken: boolean;
        updatedAt: number;
        expiresAt: number | null;
        accountEmail: string | null;
      }
    >();

    for (const row of rows) {
      const rowSubject = row.subject ?? SYSTEM_SUBJECT;
      if (rowSubject !== subject) continue;

      const existing = byProvider.get(row.provider);
      if (!existing || row.updatedAt > existing.updatedAt) {
        byProvider.set(row.provider, {
          provider: row.provider,
          subject,
          authorized: true,
          hasRefreshToken: Boolean(row.refreshTokenEncrypted),
          updatedAt: row.updatedAt,
          expiresAt: row.expiresAt ?? null,
          accountEmail: row.accountEmail ?? null
        });
      }
    }

    return [...byProvider.values()].sort((a, b) => a.provider.localeCompare(b.provider));
  }
});

