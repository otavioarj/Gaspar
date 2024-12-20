package br.gasparzinho;

import java.util.UUID;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Files extends Gaspar {

    protected static void doFileHooks(Object param ) throws Exception{
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        try {
            XposedHelpers.findAndHookConstructor("java.io.File", lpparam.classLoader, "java.lang.String", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String tmp;
                    for (String filename : denylist) {
                        tmp = (String) param.args[0];
                        if (Mycontains(tmp,filename)) {
//                         printMe(lpparam.packageName, pfile, param.getResult().toString());
                            param.args[0] = UUID.randomUUID().toString();
                            break;
                        }
                    }
                    super.beforeHookedMethod(param);
                }
            });

            XposedHelpers.findAndHookConstructor("java.io.File", lpparam.classLoader, "java.lang.String", "java.lang.String", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String tmp;
                    for (String filename : denylist) {
                        tmp = (String) param.args[0];
                        if (Mycontains(tmp,filename)) {
//                         printMe(lpparam.packageName, pfile, param.getResult().toString());
                            param.args[0] = UUID.randomUUID().toString();
                            break;
                        }
                    }
                    super.beforeHookedMethod(param);
                }
            });

            /*XposedHelpers.findAndHookMethod("java.io.File", lpparam.classLoader, "exists", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    //Object gN= XposedHelpers.getObjectField(param.thisObject,"getName");
                    String pfile = ((File) param.thisObject).getName();
                    if (pfile != null) {
                        for (String filename : denylist) {
                            if (pfile.contains(filename)) {
                                printMe(lpparam.packageName, pfile, param.getResult().toString());
                                param.setResult(false);
                                break;
                            }
                        }
                    } else {
                        printMe(lpparam.packageName,": J.IO Null Object");
                    }
                    super.afterHookedMethod(param);
                }
            });
        } catch (XposedHelpers.ClassNotFoundError e){printMe(lpparam.packageName,e.getLocalizedMessage());}*/

        } catch (XposedHelpers.ClassNotFoundError  | java.lang.NoSuchMethodError e) {
            printMe("!Err: ", lpparam.packageName, e.getLocalizedMessage());
        } catch (Exception e) {
                printMe("Trows: ", e.getLocalizedMessage());
                throw e;
        }
    }
}

