#!/usr/bin/env node
/**
 * Build script — copies the Python sources the published server needs into the
 * npm package bundle.
 *
 * WIRED TO THE PACKAGE LIFECYCLE — do not rely on anyone running this by hand.
 * `package.json` declares `"prepack": "node scripts/build.js"`, so npm runs it
 * immediately before it assembles a tarball, on BOTH `npm pack` and `npm publish`
 * (and on install-from-git). It used to say only "Run before `npm publish`" and
 * nothing invoked it, so every published tarball shipped
 * `python/mcp_server/__init__.py` and no server: `npx @arkheia/mcp-server` died in
 * ModuleNotFoundError on a customer's first run while every test passed, because a
 * git checkout has the whole repo on sys.path.
 *
 * `prepack` rather than `prepublishOnly` deliberately: `prepublishOnly` does not
 * run on `npm pack`, so no check could observe whether it works without actually
 * publishing. `tests/test_packed_artifact_floor.py` runs the real pack and asserts
 * the tarball's contents, which only works if the hook fires at pack time.
 *
 * ───────────────────────────────────────────────────────────────────────────────
 * THE COPY SET IS DERIVED, NOT DECLARED — and that is the whole point.
 * ───────────────────────────────────────────────────────────────────────────────
 * This repo has now suffered the same failure class three times (#19, #23, and
 * again when a new `mcp_server -> proxy.audit.writer` edge landed): a copy set
 * that was *written down* diverged from the imports that actually exist, and the
 * divergence was invisible from a git checkout, because a checkout has the whole
 * repo on sys.path. Every previous cure was a better-written declaration. A
 * declaration is a claim about the import graph, and a claim can be wrong.
 *
 * Worse, a declared list is only ever wrong *in combination*: the branch that adds
 * the cross-package import does not touch this file, and the branch that maintains
 * this file does not have the import. Each is correct alone, so no branch-local
 * check can see it and it bites at the merge (DONE.md v1.18, union-scoped guards).
 *
 * So this script does not declare the set. It ASKS the import graph, via the same
 * resolver the packaging floor uses (`tests/floor_support/import_closure.py`),
 * and copies exactly what comes back. A new cross-package import is shipped
 * because it exists, not because someone remembered to add it.
 *
 * Two invariants hold this together, and both are checked by
 * `tests/test_bundle_cross_package_import_floor.py`:
 *   - ENTRY_MODULE below equals the module the Node launcher actually spawns.
 *   - a cross-package import injected into the entry package reaches the tarball.
 *
 * Manual use (still supported, e.g. to inspect the bundle):
 *   node scripts/build.js
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const BUNDLE_ROOT = path.resolve(__dirname, "..", "python");

/**
 * The module `bin/arkheia-mcp.js` spawns as `python -m <ENTRY_MODULE>`. It is
 * written here because a build script cannot import the launcher (requiring it
 * would run it), and it is kept honest by a floor assertion that compares this
 * literal against the launcher's own spawn expression.
 */
const ENTRY_MODULE = "mcp_server.server";

/**
 * The entry package ships WHOLE, not just its import closure.
 *
 * Today the closure of `mcp_server.server` happens to be every `.py` under
 * `mcp_server/`, so this changes nothing — it is a deliberate conservatism, not a
 * measurement. An import-graph walk cannot see a module loaded by name at runtime,
 * and narrowing the entry package to its static closure would silently drop one.
 * Everything OUTSIDE the entry package ships exactly what the graph requires,
 * because that is where the shipped-too-little defect has actually occurred and
 * where shipping a whole sibling package (`proxy/` pulls fastapi, uvicorn,
 * cryptography, PyJWT — none of them declared by the bundle) would be wrong.
 */
const ENTRY_PACKAGE = ENTRY_MODULE.split(".")[0];

/** The shared import-graph resolver. Also used by the packaging floors. */
const CLOSURE_TOOL = path.join(
  REPO_ROOT,
  "tests",
  "floor_support",
  "import_closure.py"
);

const SKIP_NAMES = new Set(["__pycache__", "tests"]);

function fail(message) {
  process.stderr.write(`[build] ${message}\n`);
  process.exit(1);
}

/**
 * A Python 3 interpreter able to run the closure resolver.
 *
 * Deliberately NOT shared with `bin/arkheia-mcp.js` `findPython()`: that one
 * resolves the interpreter a CUSTOMER will run the server with (>=3.10, then a
 * venv, then pip install). This one resolves a BUILD-time interpreter on the
 * machine cutting the release, needs nothing but `ast` and `pathlib`, and must
 * never trigger the customer-side venv/pip path. Same word, different question.
 */
function findBuildPython() {
  for (const cmd of ["python3", "python"]) {
    try {
      const version = execFileSync(cmd, ["--version"], {
        encoding: "utf-8",
        timeout: 10000,
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
      const match = version.match(/Python (\d+)\.(\d+)/);
      if (match && Number(match[1]) === 3 && Number(match[2]) >= 8) {
        return cmd;
      }
    } catch {
      // try the next candidate
    }
  }
  return null;
}

/**
 * Repo-relative POSIX paths the published entry point transitively imports.
 *
 * Every failure here is FATAL. A build that cannot determine what to ship has not
 * determined that there is nothing to ship — "not observed" must not land in the
 * pass bucket (DONE.md floor-ledger clause 9d). Failing the pack is loud and
 * recoverable; shipping a bundle assembled from a guess is neither.
 */
function requiredSources() {
  const python = findBuildPython();
  if (!python) {
    fail(
      "no Python 3.8+ interpreter found on PATH, so the import closure of " +
        `${ENTRY_MODULE} cannot be computed and this build does not know what to ` +
        "copy. Install Python 3 and re-run. (Publishing this package has always " +
        "required Python: the server it wraps is Python, and the launcher refuses " +
        "to start without a 3.10+ interpreter.)"
    );
  }
  if (!fs.existsSync(CLOSURE_TOOL)) {
    fail(
      `the shared import-graph resolver is missing at ${CLOSURE_TOOL}. The copy ` +
        "set is derived from it, so without it this build cannot know what the " +
        "server imports. If the resolver moved, update CLOSURE_TOOL here in the " +
        "same change — do not reintroduce a hand-written source list."
    );
  }

  let stdout;
  try {
    stdout = execFileSync(python, [CLOSURE_TOOL, "--entry", ENTRY_MODULE], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 120000,
      stdio: ["ignore", "pipe", "inherit"],
    });
  } catch (err) {
    fail(
      `the import-graph resolver failed for ${ENTRY_MODULE} (${err.message}). ` +
        "Its stderr is above. The copy set is unknown, so the pack is aborted."
    );
  }

  let sources;
  try {
    sources = JSON.parse(stdout);
  } catch (err) {
    fail(
      `the import-graph resolver did not emit JSON (${err.message}). Output was:` +
        `\n${stdout}`
    );
  }
  if (!Array.isArray(sources) || sources.length === 0) {
    fail(
      `the import-graph resolver returned ${JSON.stringify(sources)} for ` +
        `${ENTRY_MODULE}. An empty closure is an unanswered question, not an ` +
        "empty bundle."
    );
  }
  if (!sources.some((s) => s.split("/")[0] === ENTRY_PACKAGE)) {
    fail(
      `the import-graph resolver returned nothing under ${ENTRY_PACKAGE}/ ` +
        `(${JSON.stringify(sources)}), so it did not walk the entry point.`
    );
  }
  return sources;
}

function copyDir(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (SKIP_NAMES.has(entry.name)) continue;
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else if (entry.name.endsWith(".py")) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

/**
 * Copy one repo-relative source to the SAME relative path under the bundle root.
 * Path-preserving by construction, so an import path in the repo is the identical
 * import path in the bundle.
 */
function copySource(source) {
  const src = path.resolve(REPO_ROOT, source);
  const dest = path.join(BUNDLE_ROOT, source);

  if (!fs.existsSync(src)) {
    fail(`required source "${source}" does not exist at ${src}`);
  }

  console.log(`Copying ${source}`);
  if (fs.statSync(src).isDirectory()) {
    copyDir(src, dest);
  } else {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(src, dest);
  }
}

const required = requiredSources();

// The entry package whole; everything else exactly as required. Sorted so the
// build log reads the same way twice.
const outsideEntry = required
  .filter((s) => s.split("/")[0] !== ENTRY_PACKAGE)
  .sort();

console.log(
  `Bundle sources derived from the import closure of ${ENTRY_MODULE}: ` +
    `${ENTRY_PACKAGE}/ (whole) + ${outsideEntry.length} cross-package file(s)`
);

copySource(ENTRY_PACKAGE);
for (const source of outsideEntry) {
  copySource(source);
}

console.log("Build complete. Run `npm publish` from npm-wrapper/.");
