package com.axcel.modifier;

public final class Native {
    static {
        System.loadLibrary("axcel");
    }

    private Native() {}

    public static native String listProcesses();

    public static native String attach(int pid);

    public static native String search(String query);
}
