import pathlib
p = pathlib.Path(r"D:\去签名\LSPatch\patch-loader\src\main\java\org\lsposed\lspatch\loader\LSPApplication.java")
s = p.read_text(encoding="utf-8")
old = """            appInfo.sourceDir = cacheApkPath.toString();
            appInfo.publicSourceDir = cacheApkPath.toString();"""
new = """            // [mixsign] 保持真实安装路径：App 的类从真实 APK 的 classesN.dex 加载，
            // 缓存里的原包只用于 openat 重定向（文件级签名读取）。
            // 原来的两行会把 sourceDir/publicSourceDir 指到 cache/lspatch/origin/*.apk，
            // 被 Package(Path) / ApkFDPath / LoadAPKRes 三项反篡改检测抓到。"""
assert old in s, "pattern not found"
p.write_text(s.replace(old, new, 1), encoding="utf-8")
print("patched LSPApplication.java")
