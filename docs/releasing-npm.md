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
kept in GitHub once it's set up. npm only lets you add a trusted publisher to
a package that already exists, so the first publish of each package uses a
token:

1. Create the `keyseal` organisation on npmjs.com, and turn on two-factor
   authentication for your account.
2. Create a granular access token that can read and write packages in the
   `keyseal` scope, valid for a day, and add it to the repository's `npm`
   environment:

   ```sh
   gh secret set NPM_TOKEN --env npm
   ```

3. Push `server-v0.1.0` and `browser-v0.1.0` as in the steps above.
4. Add the trusted publisher for each package, either from the package's
   Settings page on npmjs.com (repository `somus/keyseal`, workflow
   `npm.yml`, environment `npm`) or with npm 11.15 or later:

   ```sh
   npm trust github @keyseal/server --repo somus/keyseal --file npm.yml --env npm --allow-publish
   npm trust github @keyseal/browser --repo somus/keyseal --file npm.yml --env npm --allow-publish
   ```

5. On each package's Settings page, set Publishing access to "Require
   two-factor authentication and disallow tokens".
6. Delete the secret and revoke the token:

   ```sh
   gh secret delete NPM_TOKEN --env npm
   ```
