package br.gasparzinho;


import java.lang.reflect.Method;
import java.util.Arrays;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.XposedBridge;
//import android.annotation.SuppressLint;
import android.app.AndroidAppHelper;
//import java.lang.reflect.Field;
//import java.util.UUID;
//import java.util.Vector;
//import android.content.pm.ApplicationInfo;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Extras extends Gaspar{

    protected static void doSELinux(Object app ) throws Exception {
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) app;
        try {
            XposedHelpers.findAndHookMethod("android.os.SELinux", lpparam.classLoader, "isSELinuxEnabled", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(true);
                }
            });
        }catch (XposedHelpers.ClassNotFoundError | java.lang.NoSuchMethodError e) { printMe("!Err: ",lpparam.packageName, e.getLocalizedMessage()); }
        catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }
    }
    protected static void doStringsCmp(Object app ) throws Exception {
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) app;
        try{
            String names[]={"equals","equalsIgnoreCase","compareTo","contains"};
            Method method;
            for(String name:names){
                switch (name) {
                    case "contains":
                        method = String.class.getMethod(name, CharSequence.class);
                        break;
                    case "equals":
                        method = String.class.getMethod(name, Object.class);
                     break;
                    default:
                        method = String.class.getMethod(name, String.class);
                }
                    XposedBridge.hookMethod(method,new XC_MethodHook(){
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            //String thisString = param.thisObject.toString();
                            if (param.args[0]!=null){
                                String cmpStr = param.args[0].toString();
                                for (String deny : denylist) {
                                    if (Mycontains(cmpStr,deny)) {//
                                        param.setResult(false);
                                        return;
                                    }
                                }
                            }
                            super.beforeHookedMethod(param);
                        }
                    });
                }
        } catch (XposedHelpers.ClassNotFoundError | java.lang.NoSuchMethodError e) { printMe("!Err: ",lpparam.packageName, e.getLocalizedMessage()); }
        catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }
    }


    protected static void doStackTraces(Object app ) throws Exception {
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) app;
        try{
            XposedHelpers.findAndHookMethod("java.lang.Throwable", lpparam.classLoader, "getStackTrace", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    StackTraceElement s_trace[] = (StackTraceElement[]) param.getResult();
                    StackTraceElement out_trace[] = {};
                    for (String name : denylist)
                        for (StackTraceElement element : s_trace) {
                            if (!Mycontains(element.toString(),name)) {
                                out_trace = Arrays.copyOf(out_trace, out_trace.length + 1);
                                out_trace[out_trace.length - 1] = element;
                            }
                        }
                    param.setResult(out_trace);
                   // printMe(lpparam.packageName, "StackTrace");
                   // super.afterHookedMethod(param);
                }
            });

            XposedHelpers.findAndHookMethod("java.lang.Throwable", lpparam.classLoader, "setStackTrace",StackTraceElement[].class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    StackTraceElement[] s_trace = (StackTraceElement[]) param.args[0];
                    Throwable throwable = (Throwable) param.thisObject;
                    printMe(lpparam.packageName, "StackTrace Manipulation:");
                    for (StackTraceElement element : s_trace) {
                        printMe(element.toString());
                    }
                    printMe(lpparam.packageName, "StackTrace real:");
                    StackTraceElement[] stackTrace = throwable.getStackTrace();
                    for (StackTraceElement element : stackTrace) {
                         printMe(lpparam.packageName, element.toString());
                    }
                    // super.afterHookedMethod(param);
                    return;
                }
            });
        } catch (XposedHelpers.ClassNotFoundError | java.lang.NoSuchMethodError e) { printMe("!Err: ",lpparam.packageName, e.getLocalizedMessage()); }
            catch (Exception e) {
                printMe("Trows: ", e.getLocalizedMessage());
                throw e;
        }
    }

    protected static void doSysProps(Object app ) throws Exception {
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) app;
        try{
                XposedHelpers.findAndHookMethod("android.os.SystemProperties", lpparam.classLoader, "get",String.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        String key = (String) param.args[0]; //&& Mycompare((String) param.getResult(),"0")
                        if ((Mycompare(key,"ro.build.selinux") || Mycompare(key,"ro.secure"))) {
                            param.setResult(1);
                        } else if (Mycompare(key,"ro.debuggable") || Mycompare(key,"service.adb.root")) {
                            param.setResult(0);
                        }
                        printMe(lpparam.packageName, "SysProp: " + key+" ret:"+ param.getResult());
                    }
                });
        } catch (XposedHelpers.ClassNotFoundError  e) { printMe("!Err: ",lpparam.packageName, e.getLocalizedMessage());
        }   catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }
    }

//TODO fix exec to after and edit streams, for instance if the app detect errors while
// executing getprops; right now the error is command not found
    protected static void doExec(Object app ) {
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) app;
        try{
            XposedBridge.hookAllMethods(Runtime.class, "exec", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args[0] instanceof String) {
                        printMe("Exec:" +(String)param.args[0]);
                       for(String cmd:denylist) {
                           if (Mycontains((String) param.args[0],cmd))
                           {
                               param.args[0]=Utils.RandPkg();
                               break;
                           }
                       }
                    } else if (param.args[0] instanceof String[]) {
                        String params[]=(String[]) param.args[0];
                        printMe("Exec[]: "+Arrays.toString((String[])param.args[0]));
                        for (int i = 0; i <params.length; i++) {
                            for (String cmd : denylist) {
                                if (Mycontains(params[i], cmd)) {
                                    params[i] = Utils.RandPkg();
                                    break;
                                }
                            }
                        }
                        param.args[0]=params;
                    }
                    super.beforeHookedMethod(param);
                }
            });
        } catch (XposedHelpers.ClassNotFoundError | java.lang.NoSuchMethodError e) { printMe("!Err: ",lpparam.packageName, e.getLocalizedMessage());
        }   catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }
    }
}
