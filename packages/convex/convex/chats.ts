import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireActiveUser } from "./auth";

export const list = query({
  args: {},
  handler: async (ctx) => {
    const { user } = await requireActiveUser(ctx);
    return await ctx.db
      .query("chats")
      .withIndex("by_user", (q) => q.eq("userId", user._id))
      .collect();
  }
});

export const create = mutation({
  args: { title: v.string() },
  handler: async (ctx, args) => {
    const { user } = await requireActiveUser(ctx);
    const now = Date.now();
    const id = await ctx.db.insert("chats", {
      userId: user._id,
      title: args.title,
      createdAt: now,
      updatedAt: now
    });
    return { id };
  }
});
