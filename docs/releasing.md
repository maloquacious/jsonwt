# Release checklist

Git tags are the source of truth for jsonwt versions. The package intentionally
has no separately maintained version constant or function.

Use this checklist to release `v1.0.0`:

1. Confirm every blocker listed in the v1 tracking issue is closed. Do not tag
   while a blocker remains open.
2. Confirm `main` is checked out, synchronized with `origin/main`, and clean:

   ```sh
   git switch main
   git pull --ff-only origin main
   test -z "$(git status --short)"
   ```

3. Review the README, tutorial, how-to guides, API documentation, token-format
   reference, compatibility policy, security explanation, and known
   limitations for consistency with the code.
4. Change the `CHANGELOG.md` heading `1.0.0 (unreleased)` to
   `1.0.0 - YYYY-MM-DD`, commit that change, and wait for CI on `main` to pass.
5. From the clean release commit, run the same checks used by CI:

   ```sh
   test -z "$(gofmt -l $(find . -type f -name '*.go'))"
   go test ./...
   go vet ./...
   go build ./...
   ```

6. Confirm the module identity and absence of an existing release tag:

   ```sh
   test "$(go list -m)" = "github.com/mdhender/jsonwt"
   test -z "$(git tag --list v1.0.0)"
   ```

   The v1 module path is `github.com/mdhender/jsonwt`; Go modules do not add a
   `/v1` suffix.

7. Create and verify an annotated tag on that exact commit:

   ```sh
   git tag -a v1.0.0 -m "Release v1.0.0"
   test "$(git describe --exact-match --tags HEAD)" = "v1.0.0"
   ```

8. Push the tag, then create the GitHub release from `CHANGELOG.md`:

   ```sh
   git push origin v1.0.0
   gh release create v1.0.0 --verify-tag --title "jsonwt v1.0.0" --notes-file CHANGELOG.md
   ```

9. Verify the release page points at the intended commit and that
   `go list -m github.com/mdhender/jsonwt@v1.0.0` resolves successfully.
