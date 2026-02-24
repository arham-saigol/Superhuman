import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  allowed_users: defineTable({
    email: v.string(),
    addedBy: v.optional(v.string()),
    note: v.optional(v.string()),
    addedAt: v.number()
  }).index("by_email", ["email"]),

  users: defineTable({
    email: v.string(),
    status: v.union(v.literal("active"), v.literal("inactive")),
    createdAt: v.number(),
    updatedAt: v.number()
  }).index("by_email", ["email"]),

  chats: defineTable({
    userId: v.id("users"),
    title: v.string(),
    createdAt: v.number(),
    updatedAt: v.number()
  }).index("by_user", ["userId"]),

  messages: defineTable({
    userId: v.id("users"),
    chatId: v.id("chats"),
    role: v.union(v.literal("user"), v.literal("assistant"), v.literal("system")),
    content: v.string(),
    createdAt: v.number()
  }).index("by_user_chat", ["userId", "chatId"]),

  task_metadata: defineTable({
    userId: v.id("users"),
    chatId: v.id("chats"),
    state: v.string(),
    attempt: v.number(),
    maxAttempts: v.number(),
    input: v.string(),
    lastError: v.optional(v.string()),
    createdAt: v.number(),
    updatedAt: v.number()
  }).index("by_user", ["userId"]),

  task_events: defineTable({
    userId: v.id("users"),
    taskId: v.id("task_metadata"),
    type: v.string(),
    payloadJson: v.string(),
    createdAt: v.number()
  }).index("by_task", ["taskId"]),

  oauth_tokens_encrypted: defineTable({
    userId: v.optional(v.id("users")),
    subject: v.optional(v.string()),
    provider: v.string(),
    accountEmail: v.optional(v.string()),
    tokenType: v.optional(v.string()),
    scope: v.optional(v.string()),
    accessTokenEncrypted: v.string(),
    refreshTokenEncrypted: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    createdAt: v.number(),
    updatedAt: v.number()
  })
    .index("by_user_provider", ["userId", "provider"])
    .index("by_provider", ["provider"]),

  provider_settings: defineTable({
    userId: v.id("users"),
    provider: v.string(),
    payloadJson: v.string(),
    updatedAt: v.number()
  }).index("by_user_provider", ["userId", "provider"])
});
