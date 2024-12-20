package br.gasparzinho;


import dalvik.system.DexClassLoader;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

import dalvik.system.PathClassLoader;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class ExRunner extends Gaspar {
    protected static  void executeJavaCode(Object app) throws Throwable {
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) app;

        try {
            File tempDir = new File("/data/local/tmp/files");
            if (!tempDir.exists()) {
                tempDir.mkdirs();
            }
            File tempFile = new File(tempDir,lpparam.packageName+".dex");
            while (!tempFile.exists() ) {
                Thread.sleep(1250);
            }
            /*DexClassLoader classLoader = new DexClassLoader(
                    tempFile.getAbsolutePath(),
                    tempDir.getAbsolutePath(),
                    null,
                    ClassLoader.getSystemClassLoader().getParent()
            );*/
            PathClassLoader classLoader = new PathClassLoader(tempFile.getAbsolutePath(), lpparam.classLoader);
            Class<?> dynamicClass = classLoader.loadClass("GasparMinion");
            Object instance = dynamicClass.newInstance();
            Method met=dynamicClass.getMethod("runner",Object.class);
            List<String> metodos = (List<String>) met.invoke(instance,app);

            for (String metodo : metodos) {
                printMe(metodo);
            }
            tempFile.delete();

        } catch (InvocationTargetException e){
            Throwable targetException = e.getTargetException();
            printMe(targetException.getLocalizedMessage());
        }
        catch (Exception e) {
            printMe(e.toString());
            throw e;
        }


    }
}
