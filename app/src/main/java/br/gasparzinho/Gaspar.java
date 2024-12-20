package br.gasparzinho;

// https://github.com/stirante/Instaprefs/blob/master/app/src/main/java/com/stirante/instaprefs/InstaprefsModule.java

import android.app.AndroidAppHelper;
/*import android.app.Application;
import android.content.pm.ApplicationInfo;
import android.os.Build;*/
import android.app.Application;
import android.content.Context;
import android.util.Log;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
//import java.util.List;

import de.robv.android.xposed.IXposedHookLoadPackage;
//import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
//import de.robv.android.xposed.IXposedHookZygoteInit;
//import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Gaspar implements IXposedHookLoadPackage {

    //private String[] apps = new String[]{"com.microsoft.windowsintune.companyportal", "com.yammer.v1"};
   static String[] denylist={};//new String[]{"magi","resetprop","/su"," su","frida","lsposed","xposed","gaspar","app_process","libmemtrack","busybox","/system ", "/etc "};
   private static Boolean is_denylUpdated;
   private static String packname="Zygote";
   public static void update_denylist(String[] list){
        for(String str : list){
            denylist= Arrays.copyOf(denylist, denylist.length + 1);
            denylist[denylist.length - 1] = str;
        }
        is_denylUpdated=true;
    }

    static {
        System.loadLibrary("gasparzinho");
    }
    protected static boolean Mycontains(String str, String substring) {

        if (substring.charAt(0)=='*') {
            return Mycompare(str, substring.substring(1));
        }
        if (substring.length() > str.length()) {
            return false;
        }
        for (int i = 0; i <= str.length() - substring.length(); i++) {
            boolean found = true;
            for (int j = 0; j < substring.length(); j++) {
                if (Character.toLowerCase(str.charAt(i + j)) != Character.toLowerCase(substring.charAt(j))) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return true;
            }
        }
        return false;
    }

    protected static boolean Mycompare(String str1, String str2) {
        if (str1.length() != str2.length()) {
            return false;
        }
        for (int i = 0; i < str1.length(); i++) {
            if (str1.charAt(i) != str2.charAt(i)) {
                return false;
            }
        }
        return true;
    }
    public static void printMe(String... values){
        Log.i("[Gaspar]",packname+": "+Arrays.toString(values));
    }
    public static native void JNI_SetPackName(String name);
//    public static native void JNI_SetDenyList(String denylist);

/*
// insert IXposedHookZygoteInit to implements
public void initZygote(StartupParam startupParam) throws Throwable {
        XSharedPreferences prefs = new XSharedPreferences("br.gasparzinho");
        prefs.makeWorldReadable();
    }*/

    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        printMe("Loaded in: " + lpparam.packageName);
        packname=lpparam.packageName;
        List<String> classes;
        ClassLoader appcl = (ClassLoader) XposedHelpers.callMethod(XposedHelpers.findClass("android.app.Application", lpparam.classLoader),"getClassLoader");
        JNI_SetPackName(lpparam.packageName);

        Runs runs= new Runs(lpparam);
        while (!is_denylUpdated){
            Thread.sleep(10);
        }
        try {
            runs.exec(Files::doFileHooks);
            //runs.exec(TLS::doMassVerifier);
            runs.exec(Packages::doGetAppInfoUuid);
            runs.exec(Packages::doGetInstalledApps);
            //runs.exec(ExRunner::executeJavaCode);
            runs.exec(Extras::doSELinux);
            runs.exec(Extras::doStringsCmp);
            runs.exec(Extras::doSysProps);
            runs.exec(Extras::doStackTraces);
            runs.exec(Extras::doExec);
            runs.exec(TLS::doTrustManagerImpl);
            runs.exec(TLS::doHttpsURLConnection);
            runs.exec(TLS::doOkHttp);
            runs.exec(()->ClassesL.doClassfind(appcl));
            /*runs.exec(()->Decomp.decompile(appcl,"??....LoginDeeplinkHandler","handleSynchronously",false));
            classes=Utils.getClassNames(lpparam);
            for(String cls:classes){
                printMe(cls);
            }*/
        }catch (Throwable e){ throw e;}
    }
}
