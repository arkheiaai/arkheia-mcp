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
 * ───────────────────────────────────────────────────────────────────────────────
 * A DERIVED COPY SET IS NOT A DERIVED ARTIFACT — the destination is cleaned first.
 * ───────────────────────────────────────────────────────────────────────────────
 * The paragraph above was right and incomplete, and a second vendor proved it: the
 * copy was ADDITIVE. It copied the derived set OVER whatever was already in
 * `npm-wrapper/python`, and `package.json` ships all of `python/`, so anything ever
 * generated there stayed and shipped. A stale `python/proxy/_stale_should_not_ship.py`
 * survived a real `npm pack` while the resolver closure contained no `proxy` file at
 * all. The floor asserted that everything REQUIRED was present; nothing asserted that
 * everything PRESENT was required — a check that can only fail in the one direction
 * somebody thought of.
 *
 * So the build now REMOVES before it copies, and the tree is a function of the graph
 * plus one named, justified exception list, rather than an accumulation. See
 * `HAND_MAINTAINED` for how generated is told apart from hand-maintained, and
 * `tests/test_packed_artifact_floor.py` for the both-directions assertion against
 * the real tarball.
 *
 * Manual use (still supported, e.g. to inspect the bundle):
 *   node scripts/build.js
 *
 * Query mode (used by the packaging floor so the exception list has ONE source):
 *   node scripts/build.js --print-hand-maintained
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

/**
 * The ONLY paths under the bundle root this build does not generate.
 *
 * Bundle-relative POSIX paths. Everything else under `npm-wrapper/python` is build
 * output and is deleted before each copy, so the tree cannot accumulate.
 *
 * HOW GENERATED WAS TOLD APART FROM HAND-MAINTAINED — two independent signals had
 * to agree, because either one alone gets it wrong:
 *
 *  1. WHAT THIS SCRIPT CAN WRITE. `copySource` writes only to
 *     `BUNDLE_ROOT/<repo-relative path>`, and the resolver only ever returns `.py`
 *     files whose first segment is a first-party root package (a top-level repo
 *     directory containing `__init__.py`). `copyDir` additionally copies `.py` only.
 *     So the build's output set is exactly `python/<first-party-root>/**.py`, and
 *     nothing outside that shape can have come from here.
 *  2. WHO PRODUCES AND READS IT. `python/requirements.txt` is written by hand — it
 *     carries hand-authored CVE pins and their comments — and is read at runtime by
 *     `bin/arkheia-mcp.js` as the pip install list for a customer. No copy step
 *     produces it: the repo's own `mcp_server/requirements.txt` is never copied,
 *     because `copyDir` takes `.py` only.
 *
 * Git tracking is NOT the discriminator, and that is the trap worth naming:
 * `python/mcp_server/__init__.py` is committed too, yet it is pure build output (it
 * is in the closure and is rewritten every run). Classifying by "is it in git" would
 * have preserved a generated file forever. Classifying by "what can this script
 * write" is a property of the code, and is what the floor re-derives.
 *
 * Adding an entry here is adding a hole to the shipped ⊆ required assertion, so the
 * floor requires every entry to be real: it must actually ship, and it may not name
 * a path the import closure requires (an exception may not shadow a derivation).
 */
const HAND_MAINTAINED = ["requirements.txt"];

function fail(message) {
  process.stderr.write(`[build] ${message}\n`);
  process.exit(1);
}

/** Is `child` `parent` itself, or beneath it? Both must already be resolved. */
function inside(child, parent) {
  return child === parent || child.startsWith(parent + path.sep);
}

/**
 * A relative path from a caller must stay under `root` once resolved.
 *
 * Shared by the copy set (which comes back from a subprocess) and the exception
 * list (which is written above): both drive `fs` calls, so both are checked in the
 * same place rather than each trusting itself.
 */
function assertContainedUnder(relative, root, label) {
  if (typeof relative !== "string" || relative.length === 0) {
    fail(`${label} is not a path: ${JSON.stringify(relative)}`);
  }
  if (path.isAbsolute(relative) || /^[A-Za-z]:/.test(relative)) {
    fail(`${label} is an absolute path: ${relative}`);
  }
  const normalised = path.normalize(relative);
  if (normalised.split(/[\\/]/).includes("..")) {
    fail(`${label} escapes its root: ${relative}`);
  }
  const resolved = path.resolve(root, normalised);
  if (!inside(resolved, root)) {
    fail(`${label} "${relative}" resolves outside ${root}, to ${resolved}`);
  }
  return normalised;
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
  sources.forEach(assertContained);
  return sources;
}

/**
 * A path from the resolver must be repo-relative and stay inside BOTH trees.
 *
 * The copy set is now DATA CROSSING A PROCESS BOUNDARY — it comes back from a
 * subprocess as JSON and then drives `fs` writes. That is a real change in shape,
 * even though the producer is our own stdlib-only resolver reading our own repo,
 * so the containment is checked here rather than assumed: an absolute path, a
 * `..` segment, or a symlinked source that escapes would otherwise let a buggy or
 * substituted resolver read outside the repo or write outside the bundle.
 *
 * Both ends are checked, because they can fail independently: `src` is resolved
 * with symlinks followed (`realpathSync`) and must stay under the repo, and
 * `dest` must stay under the bundle root. Failure aborts the pack — a build that
 * has been asked to copy something it cannot vouch for does not get to guess.
 */
function assertContained(source) {
  const normalised = assertContainedUnder(
    source,
    BUNDLE_ROOT,
    "the resolver-supplied source"
  );
  const src = path.resolve(REPO_ROOT, normalised);

  if (!fs.existsSync(src)) {
    fail(`required source "${source}" does not exist at ${src}`);
  }
  if (!inside(fs.realpathSync(src), fs.realpathSync(REPO_ROOT))) {
    fail(
      `"${source}" resolves outside the repo, to ${fs.realpathSync(src)} — a ` +
        `symlink escaping the tree is not a bundle source`
    );
  }
}

/**
 * Recursive copy, bounded to `dest`.
 *
 * `entry.name` cannot contain a path separator, but the containment check is kept
 * anyway: it costs nothing and it means the bound holds for the whole walk rather
 * than only for the root the walk started from.
 */
function copyDir(src, dest, bound) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (SKIP_NAMES.has(entry.name)) continue;
    const srcPath = path.resolve(src, entry.name);
    const destPath = path.resolve(dest, entry.name);
    if (!destPath.startsWith(bound + path.sep)) {
      fail(`refusing to write ${destPath}, which is outside ${bound}`);
    }
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath, bound);
    } else if (entry.isFile() && entry.name.endsWith(".py")) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

/**
 * Copy one repo-relative source to the SAME relative path under the bundle root.
 * Path-preserving by construction, so an import path in the repo is the identical
 * import path in the bundle. `assertContained` has already vouched for `source`.
 */
function copySource(source) {
  assertContained(source);
  const normalised = path.normalize(source);
  const src = path.resolve(REPO_ROOT, normalised);
  const dest = path.resolve(BUNDLE_ROOT, normalised);

  console.log(`Copying ${normalised}`);
  if (fs.statSync(src).isDirectory()) {
    copyDir(src, dest, BUNDLE_ROOT);
  } else {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(src, dest);
  }
}

/**
 * Delete every generated path under the bundle root, keeping only `HAND_MAINTAINED`.
 *
 * An ALLOW-LIST, not a list of things to remove. "Remove the roots the closure
 * mentions" would leave behind exactly the debris that matters most — a tree
 * generated by an older closure, from a package that no longer exists or is no
 * longer imported — which is the case a second vendor reproduced. Removing
 * everything except a named, justified set makes the bundle a function of the
 * import graph, and makes any new unexplained file a decision somebody has to write
 * down rather than a file that quietly ships.
 *
 * Symlinks are unlinked, never followed: descending into a symlinked directory to
 * delete its contents would let a link inside the bundle reach outside it. Every
 * removal is additionally bounded to the realpath of the bundle root — the same
 * containment the copy side applies, for the same reason (this is `fs` mutation
 * driven by directory contents, so the bound is checked rather than assumed).
 */
function cleanBundle() {
  if (!fs.existsSync(BUNDLE_ROOT)) {
    return [];
  }
  const bound = fs.realpathSync(BUNDLE_ROOT);
  if (!inside(bound, fs.realpathSync(REPO_ROOT))) {
    fail(
      `the bundle root ${BUNDLE_ROOT} resolves to ${bound}, outside the repo — ` +
        "refusing to delete anything"
    );
  }

  const keep = new Set(HAND_MAINTAINED.map((p) => path.normalize(p)));
  const removed = [];

  const walk = (dir, relative) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.resolve(dir, entry.name);
      const rel = relative ? path.join(relative, entry.name) : entry.name;
      if (!absolute.startsWith(bound + path.sep)) {
        fail(`refusing to remove ${absolute}, which is outside ${bound}`);
      }
      if (entry.isDirectory() && !entry.isSymbolicLink()) {
        walk(absolute, rel);
        if (fs.readdirSync(absolute).length === 0) {
          fs.rmdirSync(absolute);
          removed.push(rel.split(path.sep).join("/") + "/");
        }
        continue;
      }
      if (keep.has(rel)) continue;
      fs.unlinkSync(absolute);
      removed.push(rel.split(path.sep).join("/"));
    }
  };

  walk(BUNDLE_ROOT, "");
  return removed;
}

/**
 * `HAND_MAINTAINED` may not shadow the derivation.
 *
 * An exception naming a file the import graph requires would exempt a real module
 * from the shipped ⊆ required check AND survive the clean, which is precisely the
 * accumulation this change removes — reintroduced by policy instead of by accident.
 */
function assertExceptionsDoNotShadow(required) {
  const derived = new Set(required.map((s) => path.normalize(s)));
  const shadowing = HAND_MAINTAINED.filter((p) => derived.has(path.normalize(p)));
  if (shadowing.length) {
    fail(
      `HAND_MAINTAINED names ${JSON.stringify(shadowing)}, which the import ` +
        "closure already requires. An exception may not shadow a derived source: " +
        "remove it from HAND_MAINTAINED and let the build generate it."
    );
  }
  for (const entry of HAND_MAINTAINED) {
    assertContainedUnder(entry, BUNDLE_ROOT, "HAND_MAINTAINED entry");
  }
}

function main() {
  const required = requiredSources();
  assertExceptionsDoNotShadow(required);

  // The entry package whole; everything else exactly as required. Sorted so the
  // build log reads the same way twice.
  const outsideEntry = required
    .filter((s) => s.split("/")[0] !== ENTRY_PACKAGE)
    .sort();

  console.log(
    `Bundle sources derived from the import closure of ${ENTRY_MODULE}: ` +
      `${ENTRY_PACKAGE}/ (whole) + ${outsideEntry.length} cross-package file(s)`
  );

  const removed = cleanBundle();
  console.log(
    `Cleaned ${removed.length} generated path(s) from the bundle, keeping ` +
      `${JSON.stringify(HAND_MAINTAINED)}`
  );

  copySource(ENTRY_PACKAGE);
  for (const source of outsideEntry) {
    copySource(source);
  }

  console.log("Build complete. Run `npm publish` from npm-wrapper/.");
}

// Query mode: print the exception list and exit, touching nothing. The packaging
// floor reads it from here so the list has exactly one source of truth — the same
// reason this build asks Python for the import graph instead of restating it.
if (process.argv.includes("--print-hand-maintained")) {
  process.stdout.write(JSON.stringify(HAND_MAINTAINED) + "\n");
} else {
  main();
}
