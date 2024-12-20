package br.gasparzinho;

import java.lang.reflect.Method;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
public class ClassesL extends Gaspar {

    protected static void doClassfind (ClassLoader loader) {

       // XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        Boolean sleeper=true;
        // Here go Java internals....
        //  hooking those methods while on JVM boot will make a tail recursion, which breaks androidx.startup.InitializationProvider
        //  this 5 seconds sleeps is a lazy solution.
        while (sleeper){
            try {
                Thread.sleep(5000);
                sleeper = false;
            }catch (InterruptedException e){
                continue;
            }
        }
        try {
            String cnames []={"java.lang.Class","java.lang.ClassLoader"};
            Class classobj=null;
            for ( String name :cnames) {
                try {
                    classobj =XposedHelpers.findClass(name,loader);
                    break;
                } catch (XposedHelpers.ClassNotFoundError e) { continue;}
            }
            Method[] methods = classobj.getDeclaredMethods();
            for (Method method : methods)
                if( Mycompare(method.getName(),"loadClass")) { //Mycompare(method.getName(),"forName")
                    XposedBridge.hookMethod(method, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            String className = (String) param.args[0];
                            for (String deny : denylist) {
                                if (className != null && Mycontains(className, deny)) {
                                    printMe("!CLASS: "+className +" "+deny);
                                    param.args[0] = className + " ";
                                }
                            }
                        }
                    });
                }
        } catch (Exception e) {
            printMe("Err: doClassfind" + e.getMessage());
        }
    }

}
