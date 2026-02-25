import assert from "node:assert/strict";
import { resolveConvexConfig, shouldSkipConvexDeploymentUrlCheck } from "./config.js";

{
  const resolved = resolveConvexConfig({
    CONVEX_SELF_HOSTED_URL: "http://127.0.0.1:3210",
    CONVEX_SELF_HOSTED_ADMIN_KEY: "self-key",
    CONVEX_URL: "https://foo.convex.cloud",
    CONVEX_ADMIN_KEY: "cloud-key"
  });
  assert.equal(resolved.mode, "self-hosted");
  assert.equal(resolved.url, "http://127.0.0.1:3210");
  assert.equal(resolved.adminKey, "self-key");
  assert.equal(resolved.skipConvexDeploymentUrlCheck, true);
}

{
  const resolved = resolveConvexConfig({
    CONVEX_URL: "https://foo.convex.cloud",
    CONVEX_ADMIN_KEY: "cloud-key"
  });
  assert.equal(resolved.mode, "cloud");
  assert.equal(resolved.skipConvexDeploymentUrlCheck, false);
}

{
  const resolved = resolveConvexConfig({
    CONVEX_URL: "http://127.0.0.1:3210",
    CONVEX_ADMIN_KEY: "local-key"
  });
  assert.equal(resolved.mode, "self-hosted");
  assert.equal(resolved.skipConvexDeploymentUrlCheck, true);
}

{
  const resolved = resolveConvexConfig({});
  assert.equal(resolved.mode, "none");
  assert.equal(resolved.url, null);
  assert.equal(resolved.adminKey, null);
}

assert.equal(shouldSkipConvexDeploymentUrlCheck("https://foo.convex.cloud"), false);
assert.equal(shouldSkipConvexDeploymentUrlCheck("http://127.0.0.1:3210"), true);

console.log("core config tests passed");
