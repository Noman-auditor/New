-keep class com.nora.tunnel.** { *; }
-keep class hev.htproxy.** { *; }
-keep class libv2ray.** { *; }
-keep class go.** { *; }

# SSH engine (JSch loads algorithms by class name)
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**
-dontwarn org.ietf.jgss.**
-dontwarn javax.naming.**
