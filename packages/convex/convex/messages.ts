import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireActiveUser } from "./auth";

export const listByChat = query({
  args: { chatId: v.id("chats") },
  handler: async (ctx, args) => {
    const { user } = await requireActiveUser(ctx);
    const chat = await ctx.db.get(args.chatId);
    if (!chat || chat.userId !== user._id) {
      throw new Error("Chat not found");
    }

    return await ctx.db
      .query("messages")
      .withIndex("by_user_chat", (q) => q.eq("userId", user._id).eq("chatId", args.chatId))
      .collect();
  }
});

export const add = mutation({
  args: {
    chatId: v.id("chats"),
    role: v.union(v.literal("user"), v.literal("assistant"), v.literal("system")),
    content: v.string()
  },
  handler: async (ctx, args) => {
    const { user } = await requireActiveUser(ctx);
    const chat = await ctx.db.get(args.chatId);
    if (!chat || chat.userId !== user._id) {
      throw new Error("Chat not found");
    }

    const id = await ctx.db.insert("messages", {
      userId: user._id,
      chatId: args.chatId,
      role: args.role,
      content: args.content,
      createdAt: Date.now()
    });

    await ctx.db.patch(args.chatId, { updatedAt: Date.now() });
    return { id };
  }
});
