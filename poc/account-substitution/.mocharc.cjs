// tsx (registered via `node --import tsx` in the test script) transpiles the .ts
// specs on the fly and shims __dirname in both CJS and ESM scopes, sidestepping
// mocha's ESM-vs-CJS loader ambiguity. This config just points mocha at the specs.
module.exports = {
  extension: ["ts"],
  spec: ["tests/**/*.ts"],
  timeout: 30000,
};
