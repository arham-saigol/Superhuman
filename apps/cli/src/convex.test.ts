import assert from "node:assert/strict";
import {
  applyConvexEnvDefaults,
  DEFAULT_SELF_HOSTED_CONVEX_URL,
  extractAdminKeyFromOutput,
  isPlaceholderSecret
} from "./convex.js";

assert.equal(isPlaceholderSecret(""), true);
assert.equal(isPlaceholderSecret("replace-with-secret"), true);
assert.equal(isPlaceholderSecret("real-secret"), false);

{
  const { values, changed } = applyConvexEnvDefaults({}, true);
  assert.equal(changed, true);
  assert.equal(values.CONVEX_SELF_HOSTED_URL, DEFAULT_SELF_HOSTED_CONVEX_URL);
  assert.equal(values.CONVEX_SELF_HOSTED_ADMIN_KEY, "");
}

{
  const { values } = applyConvexEnvDefaults(
    {
      CONVEX_URL: "http://localhost:3210"
    },
    true
  );
  assert.equal(values.CONVEX_SELF_HOSTED_URL, "http://localhost:3210");
}

{
  const input = {
    CONVEX_SELF_HOSTED_URL: "http://10.0.0.5:3210",
    CONVEX_SELF_HOSTED_ADMIN_KEY: "admin|abc"
  };
  const { values, changed } = applyConvexEnvDefaults(input, true);
  assert.equal(changed, false);
  assert.deepEqual(values, input);
}

{
  const input = {
    CONVEX_URL: "https://foo.convex.cloud"
  };
  const { values, changed } = applyConvexEnvDefaults(input, false);
  assert.equal(changed, false);
  assert.deepEqual(values, input);
}

{
  const key = extractAdminKeyFromOutput("Admin key: admin|abc123\n");
  assert.equal(key, "admin|abc123");
  const keySplitLine = extractAdminKeyFromOutput("Admin key:\nconvex-self-hosted|abc123\n");
  assert.equal(keySplitLine, "convex-self-hosted|abc123");
  assert.equal(extractAdminKeyFromOutput("no key here"), null);
}

console.log("cli convex tests passed");
