package com.passwordmanager;

public class NativeLib {

    static {
        System.loadLibrary("password_manager");
    }

    public static native boolean nativeCreateVault(String path, String masterPassword);
    public static native boolean nativeUnlockVault(String path, String masterPassword);
    public static native void nativeLockVault();
    public static native boolean nativeAddCredential(String url, String username, String password);
    public static native boolean nativeEditCredential(int id, String url, String username, String password);
    public static native boolean nativeDeleteCredential(int id);
    public static native String[] nativeSearchCredentials(String query);
    public static native String[] nativeGetAllCredentials();
    public static native boolean nativeClipCopy(String value);
    public static native void nativeClipClear();
    public static native int nativeClipGetRemaining();
    public static native void nativeClipTick();
}
