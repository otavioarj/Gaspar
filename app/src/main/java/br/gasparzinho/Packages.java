package br.gasparzinho;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import java.util.List;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Packages extends Gaspar {

    protected static void doGetInstalledApps(Object param ) throws Exception{
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        try{
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, "getInstalledApplications", int.class,new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    List<ApplicationInfo> apps= (List<ApplicationInfo>) param.getResult();
                    for (String name : denylist)
                        for (ApplicationInfo element : apps) {
                            if (Mycontains(element.packageName,name))
                                apps.remove(element);
                        }
                    param.setResult(apps);
                }
            });
        } catch (XposedHelpers.ClassNotFoundError | java.lang.NoSuchMethodError e) {
            printMe("!Err: ", lpparam.packageName, e.getLocalizedMessage());
        } catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }
    }

    protected static void doGetAppInfoUuid(Object param ) throws Exception{
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        String methods[]={"getPackageInfo","getPackageUid"};
        try{
            for(String method: methods) {
                XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, method, String.class, int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String appname = (String) param.args[0];
                        for (String name : denylist) {
                            //printMe("Names: ",name,appname);
                            if (Mycontains(appname, name)) {
                                param.args[0] = Utils.RandPkg();
                                break;
                            }
                        }
                        super.beforeHookedMethod(param);
                    }
                });
            }
        } catch (XposedHelpers.ClassNotFoundError | java.lang.NoSuchMethodError e) { printMe("!Err: ",lpparam.packageName, e.getLocalizedMessage());
        } catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }
    }
/*
    protected static void doGetAppUid(Object param ) throws Exception{
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        try{
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", lpparam.classLoader, "getPackageUid", String.class,int.class,new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String appname=(String) param.args[0];
                    for (String name : denylist)
                        if (Mycontains(appname,name)) {
                            param.args[0] = "com.peru.nas.pernas";
                            break;
                        }
                    super.beforeHookedMethod(param);
                }
            });
        } catch (XposedHelpers.ClassNotFoundError | java.lang.NoSuchMethodError e) { printMe("!Err: ",lpparam.packageName, e.getLocalizedMessage());
        } catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }
    }*/

}
