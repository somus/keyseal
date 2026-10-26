# Releasing the npm packages

`@keyseal/server` and `@keyseal/browser` are versioned and released on their
own. Pushing a `server-vX.Y.Z` or `browser-vX.Y.Z` tag runs
`.github/workflows/npm.yml`, which checks that the tag is on main and matches
the package's `version`, type-checks, tests and builds the package, and
publishes it with provenance.

## Steps

1. Bump `version` in `packages/server/package.json` or
   `packages/browser/package.json` in a pull request, and merge it.
2. Tag the merge commit and push the tag:

   ```sh
   git tag server-v0.2.0 && git push origin server-v0.2.0
   ```

3. Check the run in Actions, then the package page on npmjs.com, which shows
   the provenance of the build.

## One-time setup

The workflow authenticates with trusted publishing (OIDC), so no npm token is
kept in GitHub. npm only lets you add a trusted publisher to a package that
already exists, so a new package's first version is published by hand:

1. Turn on two-factor authentication for your npm account, and be a member of
   the `keyseal` organisation.
2. Publish the first version from a clean checkout of main, answering the 2FA
   prompt:

   ```sh
   cd packages/server && bun run build && npm publish --access public
   ```

3. Add the trusted publisher, either from the package's Settings page on
   npmjs.com (repository `somus/keyseal`, workflow `npm.yml`, environment
   `npm`) or with npm 11.15 or later:

   ```sh
   npm trust github @keyseal/server --repo somus/keyseal --file npm.yml --env npm --allow-publish
   ```

4. On the package's Settings page, set Publishing access to "Require
   two-factor authentication and disallow tokens".

Every later version goes through the steps above.
