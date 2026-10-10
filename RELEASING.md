# Releasing

Steps for maintainers. Artifacts are published to Maven Central under the verified namespace `io.github.sillwork`.

## One-time setup

1. **Signing key.** A GPG key for `Sillwork <sillwork.dev@gmail.com>` whose public key is on `keyserver.ubuntu.com` (and optionally `keys.openpgp.org`). Keep an offline backup of the private key and its revocation certificate.
2. **Publishing token.** Generate a user token at https://central.sonatype.com/usertoken and add it to `~/.m2/settings.xml`:

   ```xml
   <settings>
     <servers>
       <server>
         <id>central</id>
         <username>TOKEN_USERNAME</username>
         <password>TOKEN_PASSWORD</password>
       </server>
     </servers>
   </settings>
   ```

## Release

1. Set the release version in all three `pom.xml` files and move the `Unreleased` entries in `CHANGELOG.md` under that version with today's date.
2. Run the full build and make sure it is green:

   ```bash
   mvn clean verify
   ```

3. Sign and upload:

   ```bash
   mvn -P release clean deploy
   ```

   The `release` profile signs every artifact and uploads the bundle to Central, where it is validated but not yet public.
4. Review the deployment at https://central.sonatype.com/publishing/deployments and click **Publish**. Published versions cannot be changed or removed.
5. Tag the release and push the tag:

   ```bash
   git tag -s v1.0.0 -m "BlindCrypt 1.0.0"
   git push origin v1.0.0
   ```

## Windows notes

- Run the release from Git Bash. Its `gpg` is the one that holds the signing key, and it is not on the PowerShell `PATH`.
- If `gpg --send-keys` fails with "Try again later", the bundled `dirmngr` cannot reach `hkps://` keyservers. Use plain HKP instead:

  ```bash
  echo "keyserver hkp://keyserver.ubuntu.com:11371" >> ~/.gnupg/dirmngr.conf
  gpgconf --kill dirmngr
  ```
