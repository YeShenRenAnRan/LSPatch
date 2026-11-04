package org.lsposed.lspatch.loader;

import static org.lsposed.lspatch.share.Constants.ORIGINAL_APK_ASSET_PATH;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageParser;
import android.content.pm.Signature;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;
import android.util.Log;

import com.google.gson.JsonSyntaxException;

import org.lsposed.lspatch.loader.util.XLog;
import org.lsposed.lspatch.share.Constants;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipFile;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class SigBypass {

    private static final String TAG = "LSPatch-SigBypass";
    // Synchronized: afterHookedMethod runs on arbitrary caller threads, and a plain HashMap
    // under concurrent structural change can lose entries or throw. Null values are kept
    // (null == not a patched package), which rules out ConcurrentHashMap.
    private static final Map<String, String> signatures =
            java.util.Collections.synchronizedMap(new HashMap<>());

    /**
     * The original signature to present for a package, read from the {@code lspatch} manifest
     * metadata and cached. Null (cached) for a package that was not patched or carries no original.
     */
    private static String getReplacement(Context context, String packageName) {
        if (signatures.containsKey(packageName)) return signatures.get(packageName);
        String replacement = null;
        try {
            var metaData = context.getPackageManager()
                    .getApplicationInfo(packageName, PackageManager.GET_META_DATA).metaData;
            String encoded = metaData == null ? null : metaData.getString("lspatch");
            if (encoded != null) {
                var json = new String(Base64.decode(encoded, Base64.DEFAULT), StandardCharsets.UTF_8);
                try {
                    replacement = new JSONObject(json).getString("originalSignature");
                } catch (JSONException e) {
                    Log.w(TAG, "fail to get originalSignature", e);
                }
            }
        } catch (PackageManager.NameNotFoundException | RuntimeException ignored) {
        }
        signatures.put(packageName, replacement);
        return replacement;
    }

    private static void replaceSignature(Context context, PackageInfo packageInfo) {
        boolean hasSignature = (packageInfo.signatures != null && packageInfo.signatures.length != 0) || packageInfo.signingInfo != null;
        if (hasSignature) {
            String packageName = packageInfo.packageName;
            String replacement = getReplacement(context, packageName);
            if (replacement != null) {
                Signature original = new Signature(replacement);
                // Every signer, not only the first. An original signed by more than one key, or an
                // app that reads signatures[1..], would otherwise still see the LSPatch key in the
                // entries the old code left untouched.
                if (packageInfo.signatures != null && packageInfo.signatures.length > 0) {
                    XLog.d(TAG, "Replace signatures[] for `" + packageName + "`");
                    for (int i = 0; i < packageInfo.signatures.length; i++) {
                        packageInfo.signatures[i] = original;
                    }
                }
                if (packageInfo.signingInfo != null) {
                    XLog.d(TAG, "Replace signingInfo for `" + packageName + "`");
                    Signature[] signers = packageInfo.signingInfo.getApkContentsSigners();
                    if (signers != null) {
                        for (int i = 0; i < signers.length; i++) signers[i] = original;
                    }
                    // getApkContentsSigners() may hand back a copy; the spoof only sticks for
                    // callers that read the details object or reflect into it if the backing array
                    // inside SigningDetails is overwritten too.
                    replaceSigningDetails(packageInfo.signingInfo, original);
                }
            }
        }
    }

    /**
     * Overwrites the signature array inside a SigningInfo's backing SigningDetails.
     *
     * The field moved when SigningDetails was promoted from PackageParser$SigningDetails (a nested
     * class, field {@code signatures}) to the top-level android.content.pm.SigningDetails on Android
     * 13 (field {@code mSignatures}). Both names are tried, and any failure is swallowed: this runs
     * inside the patched app, so a reflection miss on an unfamiliar build must never take the app
     * down -- the outer getApkContentsSigners() replacement already covers the common path.
     */
    private static void replaceSigningDetails(Object signingInfo, Signature original) {
        try {
            Object details = XposedHelpers.getObjectField(signingInfo, "mSigningDetails");
            if (details == null) return;
            for (String field : new String[]{"mSignatures", "signatures"}) {
                try {
                    Object current = XposedHelpers.getObjectField(details, field);
                    if (current instanceof Signature[]) {
                        int len = Math.max(((Signature[]) current).length, 1);
                        Signature[] replaced = new Signature[len];
                        for (int i = 0; i < len; i++) replaced[i] = original;
                        XposedHelpers.setObjectField(details, field, replaced);
                        return;
                    }
                } catch (Throwable ignore) {
                }
            }
        } catch (Throwable t) {
            XLog.d(TAG, "replaceSigningDetails skipped: " + t.getMessage());
        }
    }

    private static void hookPackageParser(Context context) {
        XposedBridge.hookAllMethods(PackageParser.class, "generatePackageInfo", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                var packageInfo = (PackageInfo) param.getResult();
                if (packageInfo == null) return;
                replaceSignature(context, packageInfo);
            }
        });
    }

    private static void proxyPackageInfoCreator(Context context) {
        Parcelable.Creator<PackageInfo> originalCreator = PackageInfo.CREATOR;
        Parcelable.Creator<PackageInfo> proxiedCreator = new Parcelable.Creator<>() {
            @Override
            public PackageInfo createFromParcel(Parcel source) {
                PackageInfo packageInfo = originalCreator.createFromParcel(source);
                replaceSignature(context, packageInfo);
                return packageInfo;
            }

            @Override
            public PackageInfo[] newArray(int size) {
                return originalCreator.newArray(size);
            }
        };
        XposedHelpers.setStaticObjectField(PackageInfo.class, "CREATOR", proxiedCreator);
        try {
            Map<?, ?> mCreators = (Map<?, ?>) XposedHelpers.getStaticObjectField(Parcel.class, "mCreators");
            mCreators.clear();
        } catch (NoSuchFieldError ignore) {
        } catch (Throwable e) {
            Log.w(TAG, "fail to clear Parcel.mCreators", e);
        }
        try {
            Map<?, ?> sPairedCreators = (Map<?, ?>) XposedHelpers.getStaticObjectField(Parcel.class, "sPairedCreators");
            sPairedCreators.clear();
        } catch (NoSuchFieldError ignore) {
        } catch (Throwable e) {
            Log.w(TAG, "fail to clear Parcel.sPairedCreators", e);
        }
    }

    /**
     * Spoofs the app-local getPackageInfo path.
     *
     * The PackageParser hook catches the in-process parse and the CREATOR proxy catches results
     * unmarshalled from the system across binder; this catches ApplicationPackageManager, the front
     * door most apps actually call, including the modern GET_SIGNING_CERTIFICATES form. Belt and
     * suspenders, but the belts cover different paths.
     */
    private static void hookApplicationPackageManager(Context context) {
        try {
            Class<?> apm = Class.forName("android.app.ApplicationPackageManager");
            XposedBridge.hookAllMethods(apm, "getPackageInfo", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param.getResult() instanceof PackageInfo info) {
                        replaceSignature(context, info);
                    }
                }
            });
        } catch (Throwable t) {
            XLog.d(TAG, "hookApplicationPackageManager skipped: " + t.getMessage());
        }
    }

    /**
     * Spoofs the in-process archive parse, {@code getPackageArchiveInfo}.
     *
     * A tamper check often reads its own installed apk as a file --
     * {@code getPackageArchiveInfo(getPackageResourcePath(), GET_SIGNING_CERTIFICATES)} -- to recover
     * the signer. On API 30+ that parses the apk in-process and never routes through
     * {@code PackageParser.generatePackageInfo} nor the {@code PackageInfo} CREATOR, so neither the
     * parser hook nor the CREATOR proxy fires; without this the archive's real (LSPatch) key leaks.
     * The method is declared on {@code PackageManager} itself (not overridden in
     * ApplicationPackageManager), so it is hooked there to catch both the {@code (String,int)} and the
     * API 33 {@code (String,PackageInfoFlags)} overloads.
     *
     * {@link #replaceSignature} only rewrites a package an original is held for (getReplacement returns
     * null otherwise), so parsing a foreign archive is left untouched. At level 2+ the openat redirect
     * already makes the parse read the stored original, so this mainly closes the gap at level 1 -- it
     * is cheap belt-and-suspenders for the redirecting levels.
     */
    private static void hookPackageArchiveInfo(Context context) {
        try {
            XposedBridge.hookAllMethods(PackageManager.class, "getPackageArchiveInfo", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param.getResult() instanceof PackageInfo info) {
                        replaceSignature(context, info);
                    }
                }
            });
        } catch (Throwable t) {
            XLog.d(TAG, "hookPackageArchiveInfo skipped: " + t.getMessage());
        }
    }

    /**
     * Defeats the comparison-side check, {@code hasSigningCertificate}.
     *
     * Some integrity libraries never read the signature bytes; they hand the framework the original
     * certificate and ask whether it matches. Against a re-signed app that returns false, so the
     * answer is corrected: when the certificate presented is the app's own original -- raw X509 or
     * its SHA-256, per the {@code type} argument -- the call is forced to true. Only the app's own
     * package is answered; a genuine cross-app check is left alone.
     */
    private static void hookSigningCertificateCheck(Context context) {
        try {
            Class<?> apm = Class.forName("android.app.ApplicationPackageManager");
            XposedBridge.hookAllMethods(apm, "hasSigningCertificate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(param.getResult())) return;
                    Object[] args = param.args;
                    // Locate the certificate bytes and the type flag among the two overloads
                    // (by package name, and by uid).
                    byte[] presented = null;
                    int type = 0; // PackageManager.CERT_INPUT_RAW_X509
                    String pkg = null;
                    for (Object a : args) {
                        if (a instanceof byte[]) presented = (byte[]) a;
                        else if (a instanceof String) pkg = (String) a;
                        else if (a instanceof Integer) type = (Integer) a;
                    }
                    if (presented == null) return;
                    // Only vouch for the app's own package. The uid overload carries no name; the
                    // patched app querying itself is the case worth answering, and answering a
                    // foreign package would be a real spoof rather than a self-check.
                    String self = context.getPackageName();
                    if (pkg != null && !pkg.equals(self)) return;
                    String replacement = signatures.get(self);
                    if (replacement == null) return;
                    byte[] original = new Signature(replacement).toByteArray();
                    byte[] expected = type == 1 /* CERT_INPUT_SHA256 */ ? sha256(original) : original;
                    if (expected != null && java.security.MessageDigest.isEqual(expected, presented)) {
                        XLog.d(TAG, "hasSigningCertificate spoofed true for `" + self + "`");
                        param.setResult(true);
                    }
                }
            });
        } catch (Throwable t) {
            XLog.d(TAG, "hookSigningCertificateCheck skipped: " + t.getMessage());
        }
    }

    private static byte[] sha256(byte[] input) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Throwable t) {
            return null;
        }
    }


    // ---------------------------------------------------------------------
    // 通用路径接管（不依赖任何 App 常量，全部从 context + assets 推出来）
    // ---------------------------------------------------------------------
    private static void hookUniversal(final Context context) {
        String real = null;
        try {
            String lib = context.getApplicationInfo().nativeLibraryDir;
            if (lib != null) {
                java.io.File d = new java.io.File(lib).getParentFile();
                if (d != null && d.getParentFile() != null) {
                    real = new java.io.File(d.getParentFile(), "base.apk").getAbsolutePath();
                }
            }
        } catch (Throwable ignored) {
        }
        if (real == null) real = context.getPackageCodePath();
        final String realApk = real;

        String cache = null;
        try {
            java.io.File dir = new java.io.File(context.getCacheDir(), "lspatch/origin");
            java.io.File[] files = dir.listFiles();
            if (files != null) {
                for (java.io.File f : files) {
                    if (f.getName().endsWith(".apk")) {
                        cache = f.getAbsolutePath();
                        break;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        final String cacheApk = cache;
        CACHE_FOR_CKSUM = cache;
        XLog.d(TAG, "universal hooks: real=" + realApk + " cache=" + cacheApk);
        if (cacheApk == null) return;

        // 1) package path: answer the app with the real install path
        try {
            Class<?> ci = Class.forName("android.app.ContextImpl");
            for (String name : new String[]{"getPackageCodePath", "getPackageResourcePath"}) {
                for (var m : ci.getDeclaredMethods()) {
                    if (!m.getName().equals(name) || m.getParameterCount() != 0) continue;
                    m.setAccessible(true);
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            boolean fw = calledByFramework();
                            Object orig = param.getResult();
                            XLog.d(TAG, "path hook fired fw=" + fw + " orig=" + orig);
                            if (!fw) param.setResult(realApk);
                        }
                    });
                }
            }
        } catch (Throwable t) {
            XLog.w(TAG, "path hook failed: " + t);
        }

        // 1.5) binder 反序列化：PackageInfo$1 / ApplicationInfo$1
        try {
            Class<?> piCreator = Class.forName("android.content.pm.PackageInfo$1");
            for (var m : piCreator.getDeclaredMethods()) {
                if (!m.getName().equals("createFromParcel")) continue;
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object r = param.getResult();
                        if (!(r instanceof PackageInfo)) return;
                        PackageInfo pi = (PackageInfo) r;
                        String repl = getReplacement(context, pi.packageName);
                        if (repl == null) return;
                        // 只替换"当前签名"：哨兵/伪造的签名原样放行，否则往返一致性会断
                        int cur = REAL_SIG_HASH != 0 ? REAL_SIG_HASH : newCertHash(realApk);
                        boolean hit = cur == 0;
                        try {
                            if (!hit && pi.signatures != null && pi.signatures.length > 0) {
                                hit = pi.signatures[0].hashCode() == cur;
                            }
                        } catch (Throwable ignored) {
                        }
                        if (hit) replaceSignature(context, pi);
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "packageinfo creator hook failed: " + t);
        }

        try {
            Class<?> aiCreator = Class.forName("android.content.pm.ApplicationInfo$1");
            for (var m : aiCreator.getDeclaredMethods()) {
                if (!m.getName().equals("createFromParcel")) continue;
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object r = param.getResult();
                        if (!(r instanceof android.content.pm.ApplicationInfo)) return;
                        android.content.pm.ApplicationInfo ai = (android.content.pm.ApplicationInfo) r;
                        if (!context.getPackageName().equals(ai.packageName)) return;
                        // 平台默认值：检测项就是拿它做比较
                        ai.appComponentFactory = "android.app.AppComponentFactory";
                        ai.sourceDir = realApk;
                        ai.publicSourceDir = realApk;
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "appinfo creator hook failed: " + t);
        }

        // 1.6) getApplicationInfo: sourceDir 修回真实路径
        try {
            for (var m : Class.forName("android.app.ApplicationPackageManager").getDeclaredMethods()) {
                String n = m.getName();
                if (!n.equals("getApplicationInfo") && !n.equals("getApplicationInfoAsUser")) continue;
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object r = param.getResult();
                        if (!(r instanceof android.content.pm.ApplicationInfo)) return;
                        android.content.pm.ApplicationInfo ai = (android.content.pm.ApplicationInfo) r;
                        if (!context.getPackageName().equals(ai.packageName)) return;
                        ai.sourceDir = realApk;
                        ai.publicSourceDir = realApk;
                        if (ai.appComponentFactory != null
                                && ai.appComponentFactory.contains("lspatch")) {
                            ai.appComponentFactory = "android.app.AppComponentFactory";
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "appinfo hook failed: " + t);
        }

        // 1.7) LoadedApk.getResDir: Context 路径的另一个来源
        try {
            for (var m : Class.forName("android.app.LoadedApk").getDeclaredMethods()) {
                if (!m.getName().equals("getResDir") || m.getParameterCount() != 0) continue;
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object r = param.getResult();
                        if (r instanceof String && ((String) r).contains("lspatch/origin")) {
                            param.setResult(realApk);
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "loadedapk hook failed: " + t);
        }

        // 2) opening our own apk -> cached original
        for (String cls : new String[]{"java.util.jar.JarFile", "java.util.zip.ZipFile"}) {
            try {
                Class<?> c = Class.forName(cls);
                for (var ctor : c.getDeclaredConstructors()) {
                    if (ctor.getParameterCount() == 0) continue;
                    final Class<?> p0 = ctor.getParameterTypes()[0];
                    if (p0 != String.class && p0 != java.io.File.class) continue;
                    ctor.setAccessible(true);
                    XposedBridge.hookMethod(ctor, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object a0 = param.args[0];
                            String path = a0 instanceof java.io.File
                                    ? ((java.io.File) a0).getPath() : String.valueOf(a0);
                            if (realApk.equals(path)) {
                                param.args[0] = p0 == java.io.File.class
                                        ? new java.io.File(cacheApk) : cacheApk;
                            }
                        }
                    });
                }
            } catch (Throwable t) {
                XLog.w(TAG, "zip hook failed: " + cls + ": " + t);
            }
        }

        // 2.5) maps 文本：把本 App 的 apk 映射行 perms 改成 r--s（LoadAPKRes 要求）
        try {
            for (var ctor : java.io.FileInputStream.class.getDeclaredConstructors()) {
                if (ctor.getParameterCount() != 1 || ctor.getParameterTypes()[0] != String.class) continue;
                ctor.setAccessible(true);
                XposedBridge.hookMethod(ctor, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        if (!"/proc/self/maps".equals(param.args[0])) return;
                        try {
                            StringBuilder sb = new StringBuilder();
                            boolean changed = false;
                            try (var br = new java.io.BufferedReader(new java.io.FileReader("/proc/self/maps"))) {
                                String line;
                                while ((line = br.readLine()) != null) {
                                    if (line.contains(realApk)) {
                                        String[] f = line.split("\\s+");
                                        if (f.length >= 6 && !"r--s".equals(f[1])) {
                                            line = f[0] + " r--s " + f[2] + " " + f[3] + " " + f[4] + " " + f[5];
                                            changed = true;
                                        }
                                    }
                                    sb.append(line).append('\n');
                                }
                            }
                            if (changed) {
                                java.io.File fake = new java.io.File(context.getCacheDir(), "maps_fake.txt");
                                try (var w = new java.io.FileWriter(fake)) {
                                    w.write(sb.toString());
                                }
                                param.args[0] = fake.getAbsolutePath();
                                XLog.d(TAG, "maps rewritten -> " + fake.getAbsolutePath());
                            }
                        } catch (Throwable t) {
                            XLog.w(TAG, "maps rewrite failed: " + t);
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "maps hook failed: " + t);
        }

        // 3) shell reads: cat <apk>
        try {
            for (var m : java.lang.Runtime.class.getDeclaredMethods()) {
                if (!m.getName().equals("exec")) continue;
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        for (int i = 0; i < param.args.length; i++) {
                            Object a = param.args[i];
                            if (a instanceof String) {
                                param.args[i] = rewritePath((String) a, realApk, cacheApk);
                            } else if (a instanceof String[]) {
                                String[] arr = (String[]) a;
                                for (int k = 0; k < arr.length; k++) {
                                    arr[k] = rewritePath(arr[k], realApk, cacheApk);
                                }
                            }
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "exec hook failed: " + t);
        }

        // 4) assets listing: hide loader's own dir
        try {
            for (var m : Class.forName("android.content.res.AssetManager").getDeclaredMethods()) {
                if (!m.getName().equals("list")) continue;
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object r = param.getResult();
                        if (!(r instanceof String[])) return;
                        java.util.List<String> keep = new java.util.ArrayList<>();
                        for (String x : (String[]) r) {
                            if (x != null && x.contains("lspatch")) continue;
                            keep.add(x);
                        }
                        param.setResult(keep.toArray(new String[0]));
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "assets hook failed: " + t);
        }

        // 5) /proc/self/fd listing: hide fds into cached original
        try {
            for (var m : java.io.File.class.getDeclaredMethods()) {
                if (!m.getName().equals("listFiles") || m.getParameterCount() != 0) continue;
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object self = param.thisObject;
                        if (!(self instanceof java.io.File)) return;
                        if (!"/proc/self/fd".equals(((java.io.File) self).getPath())) return;
                        Object r = param.getResult();
                        if (!(r instanceof java.io.File[])) return;
                        java.util.List<java.io.File> keep = new java.util.ArrayList<>();
                        for (java.io.File f : (java.io.File[]) r) {
                            String cp;
                            try {
                                cp = f.getCanonicalPath();
                            } catch (Throwable e) {
                                cp = f.getPath();
                            }
                            if (cp != null && cp.contains("lspatch/origin")) continue;
                            keep.add(f);
                        }
                        param.setResult(keep.toArray(new java.io.File[0]));
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "fd hook failed: " + t);
        }

        // 6) memory segment reads -> file content
        try {
            for (var m : Class.forName("libcore.io.Memory").getDeclaredMethods()) {
                if (!m.getName().equals("peekByteArray") || m.getParameterCount() != 4) continue;
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        try {
                            long addr = (Long) param.args[0];
                            byte[] dst = (byte[]) param.args[1];
                            int off = (Integer) param.args[2];
                            int len = (Integer) param.args[3];
                            if (spoofMem(addr, dst, off, len, realApk)) param.setResult(null);
                        } catch (Throwable ignored) {
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XLog.w(TAG, "mem hook failed: " + t);
        }
    }


    private static int NEW_CERT_HASH;
    private static int REAL_SIG_HASH;

    /** 从真实 APK 的 META-INF/*.RSA 算出当前证书的 hashCode；算不出来返回 0（不启用哨兵判定） */
    private static synchronized int newCertHash(String apkPath) {
        if (NEW_CERT_HASH != 0) return NEW_CERT_HASH;
        if (apkPath == null) return 0;
        try (java.util.zip.ZipFile z = new java.util.zip.ZipFile(apkPath)) {
            var en = z.entries();
            while (en.hasMoreElements()) {
                var e = en.nextElement();
                String n = e.getName().toUpperCase(java.util.Locale.ROOT);
                if (!n.startsWith("META-INF/") || !n.endsWith(".RSA")) continue;
                try (var in = z.getInputStream(e)) {
                    var cf = java.security.cert.CertificateFactory.getInstance("X.509");
                    var certs = cf.generateCertificates(in);
                    if (certs.isEmpty()) return 0;
                    byte[] der = certs.iterator().next().getEncoded();
                    int h = 1;
                    for (byte b : der) h = 31 * h + b;
                    NEW_CERT_HASH = h;
                    XLog.d(TAG, "current cert hash = " + Integer.toHexString(h));
                }
                break;
            }
        } catch (Throwable ignored) {
        }
        return NEW_CERT_HASH;
    }

    private static boolean calledByFramework() {
        // 只认 loader 入口类；SigBypass 自己的帧也在栈里，不能匹配整个 loader 包
        for (StackTraceElement e : new Throwable().getStackTrace()) {
            String cn = e.getClassName();
            if (cn.equals("org.lsposed.lspatch.loader.LSPApplication")
                    || cn.equals("org.lsposed.lspatch.loader.LSPatchDocumentsProvider")
                    || cn.startsWith("org.lsposed.lspatch.metaloader.")) {
                return true;
            }
        }
        return false;
    }

    private static String rewritePath(String s, String from, String to) {
        if (s == null || !s.contains(from)) return s;
        String t = s.trim();
        if (!(t.startsWith("cat ") || t.startsWith("/system/bin/cat "))) return s;
        return s.replace(from, to);
    }

    // maps 缓存：地址段 -> 文件
    private static long mapsTs;
    private static final java.util.List<long[]> MAPS = new java.util.ArrayList<>();
    private static final java.util.List<String> MAPS_PATH = new java.util.ArrayList<>();

    private static synchronized void refreshMaps() {
        long now = System.currentTimeMillis();
        if (now - mapsTs < 1500 && !MAPS.isEmpty()) return;
        mapsTs = now;
        MAPS.clear();
        MAPS_PATH.clear();
        try (var br = new java.io.BufferedReader(new java.io.FileReader("/proc/self/maps"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] f = line.split("\\s+");
                if (f.length < 6) continue;
                String[] se = f[0].split("-");
                if (se.length != 2) continue;
                if (!f[5].startsWith("/")) continue;
                try {
                    MAPS.add(new long[]{Long.parseLong(se[0], 16), Long.parseLong(se[1], 16),
                            Long.parseLong(f[2], 16)});
                    MAPS_PATH.add(f[5]);
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static int DEX_CKSUM;
    private static String CACHE_FOR_CKSUM;

    private static synchronized int dexChecksum() {
        if (DEX_CKSUM != 0) return DEX_CKSUM;
        if (CACHE_FOR_CKSUM == null) return 0;
        try (java.util.zip.ZipFile z = new java.util.zip.ZipFile(CACHE_FOR_CKSUM)) {
            java.util.zip.ZipEntry e = z.getEntry("classes.dex");
            if (e == null) return 0;
            try (var in = z.getInputStream(e)) {
                byte[] h = new byte[12];
                if (in.read(h, 0, 12) < 12) return 0;
                DEX_CKSUM = (h[8] & 0xff) | ((h[9] & 0xff) << 8) | ((h[10] & 0xff) << 16) | ((h[11] & 0xff) << 24);
                XLog.d(TAG, "dex checksum = " + Integer.toHexString(DEX_CKSUM));
            }
        } catch (Throwable ignored) {
        }
        return DEX_CKSUM;
    }

    private static boolean spoofMem(long addr, byte[] dst, int off, int len, String realApk) {
        if (addr <= 0 || len <= 0) return false;
        refreshMaps();
        long cur = addr;
        int dstOff = off;
        long remaining = len;
        while (remaining > 0) {
            int hit = -1;
            for (int i = 0; i < MAPS.size(); i++) {
                long[] m = MAPS.get(i);
                if (cur >= m[0] && cur < m[1]) {
                    hit = i;
                    break;
                }
            }
            if (hit < 0) return false;
            long[] m = MAPS.get(hit);
            String path = MAPS_PATH.get(hit);
            long chunk = Math.min(remaining, m[1] - cur);
            if (path.endsWith(".vdex") && cur == m[0]) {
                int cks = dexChecksum();
                if (cks != 0) {
                    byte[] fake = new byte[(int) chunk];
                    byte[] magic = {'d', 'e', 'x', '\n', '0', '3', '5', 0};
                    System.arraycopy(magic, 0, fake, 0, 8);
                    fake[8] = (byte) (cks & 0xff);
                    fake[9] = (byte) ((cks >> 8) & 0xff);
                    fake[10] = (byte) ((cks >> 16) & 0xff);
                    fake[11] = (byte) ((cks >> 24) & 0xff);
                    System.arraycopy(fake, 0, dst, dstOff, (int) chunk);
                    cur += chunk;
                    dstOff += (int) chunk;
                    remaining -= chunk;
                    continue;
                }
            }
            long fo = m[2] + (cur - m[0]);
            String readPath = path.contains("lspatch/origin") ? realApk : path;
            try (var raf = new java.io.RandomAccessFile(readPath, "r")) {
                long avail = Math.max(0L, raf.length() - fo);
                int n = (int) Math.min(chunk, avail);
                if (n > 0) {
                    raf.seek(fo);
                    raf.readFully(dst, dstOff, n);
                }
                for (int k = n; k < chunk; k++) dst[dstOff + k] = 0;
            } catch (Throwable t) {
                return false;
            }
            cur += chunk;
            dstOff += (int) chunk;
            remaining -= chunk;
        }
        return true;
    }

    static void doSigBypass(Context context, int sigBypassLevel) throws IOException {
        if (sigBypassLevel >= Constants.SIGBYPASS_LV_PM) {
            // 先记下"真实签名"（此刻 PM 还没被 hook），后面用来区分"真签名"和"哨兵/伪造签名"
            try {
                PackageInfo self = context.getPackageManager()
                        .getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
                if (self != null && self.signatures != null && self.signatures.length > 0) {
                    REAL_SIG_HASH = self.signatures[0].hashCode();
                    XLog.d(TAG, "real sig hash = " + Integer.toHexString(REAL_SIG_HASH));
                }
            } catch (Throwable t) {
                XLog.w(TAG, "capture real sig failed: " + t);
            }
            // Prime the cache so hasSigningCertificate has the original on hand from the first call.
            getReplacement(context, context.getPackageName());
            hookPackageParser(context);
            // proxyPackageInfoCreator(context);  // 由 PackageInfo$1.createFromParcel hook 取代
            hookApplicationPackageManager(context);
            hookPackageArchiveInfo(context);
            hookSigningCertificateCheck(context);
            hookUniversal(context);
        }
        if (sigBypassLevel >= Constants.SIGBYPASS_LV_PM_OPENAT) {
            String cacheApkPath;
            try (ZipFile sourceFile = new ZipFile(context.getPackageResourcePath())) {
                var entry = sourceFile.getEntry(ORIGINAL_APK_ASSET_PATH);
                if (entry != null) {
                    cacheApkPath = context.getCacheDir() + "/lspatch/origin/" + entry.getCrc() + ".apk";
                } else {
                    cacheApkPath = null;
                }
            }
            if (cacheApkPath != null) {
                org.matrix.vector.nativebridge.SigBypass.enableOpenatHook(context.getPackageResourcePath(), cacheApkPath);
            }
        }
        if (sigBypassLevel >= Constants.SIGBYPASS_LV_PM_OPENAT_SVC) {
            // Reuses the apk paths enableOpenatHook just recorded; must run after it.
            org.matrix.vector.nativebridge.SigBypass.enableSvcRedirect();
        }
    }
}
