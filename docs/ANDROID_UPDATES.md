# Android: installing updates without losing your vault

## Why "App not installed / package conflicts" happens

Android refuses to update an installed app in place when the new APK is **signed
with a different key** than the installed one. Debug APKs are normally signed with
an auto-generated debug key that differs between machines and between CI runs, so
each new `app-debug.apk` had a different signature — hence the conflict, and the
only way to install was to uninstall first (which deletes the app's private
`files/vault.vlt`).

## The fix (committed stable debug key)

The repo now includes a **fixed** debug keystore at `android/debug.keystore` and
`android/app/build.gradle` signs debug (and, for now, release) builds with it:

- alias: `androiddebugkey`, store/key password: `android`
- SHA-256: `46:62:E1:93:E9:16:FF:0A:58:E3:2C:BA:04:46:67:28:F4:B4:C5:C6:1A:07:F8:D8:76:FE:BD:1D:62:2D:21:85`

From now on, every build (your machine and CI) shares this signature, so
`app-debug.apk` installs **over** the previous version and keeps the vault.

> This debug key is for development/testing only. It is intentionally a
> well-known password. Do not use it to publish to the Play Store — create a
> private release keystore for that.

## One-time migration (only needed once)

The app currently on your phone was signed with the **old** per-machine debug key,
so the *first* install of a build using the new shared key will still conflict.
Do this once, preserving your data:

1. **Back up the vault from the phone** (USB debugging on, phone connected):
   ```
   adb exec-out run-as com.passwordmanager cat files/vault.vlt > vault-backup.vlt
   ```
   Confirm `vault-backup.vlt` is non-empty.

2. **Uninstall the old app:**
   ```
   adb uninstall com.passwordmanager
   ```

3. **Install the new, stably-signed APK:**
   ```
   adb install app-debug.apk
   ```

4. **Restore the vault** into the fresh install:
   ```
   adb push vault-backup.vlt /data/local/tmp/vault.vlt
   adb shell run-as com.passwordmanager cp /data/local/tmp/vault.vlt files/vault.vlt
   adb shell run-as com.passwordmanager rm /data/local/tmp/vault.vlt
   ```

5. Open the app and unlock with your master password. Your credentials are back.

After this one-time step, all future `app-debug.apk` updates install in place with
no uninstall and no data loss.
