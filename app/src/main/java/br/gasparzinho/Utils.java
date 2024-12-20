package br.gasparzinho;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import android.os.Build;
import dalvik.system.BaseDexClassLoader;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Utils extends Gaspar{

    protected static String RandPkg() {
       String ALPHABET = "abcdefghijklmnopqrstuvwxyz";
        Random RANDOM=new Random();
        return String.format("com.%c.%c",
                ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())),
                ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
    }
/*
    protected static List<String> getMethods(XC_LoadPackage.LoadPackageParam lpparam, String className) {
        List<String> methodNames = new ArrayList<>();
        ClassLoader classLoader = lpparam.classLoader;
        try {
            Class<?> targetClass = XposedHelpers.findClass(className, classLoader);

            // Obtenha todos os métodos públicos da classe
            Method[] methods = targetClass.getDeclaredMethods();

            for (Method method : methods) {
                methodNames.add(method.getName());
            }
        } catch (Exception e) {
            printMe("!Err:",className,e.toString());
        }

        return methodNames;
    }
*/
    protected static List<String> getClassNames(XC_LoadPackage.LoadPackageParam lpparam)  {
        ClassLoader classLoader = lpparam.classLoader;
        List<String> loadedClasses = new ArrayList<>();
        try {
            if (classLoader instanceof BaseDexClassLoader) {
                Field pathListField = BaseDexClassLoader.class.getDeclaredField("pathList");
                pathListField.setAccessible(true);
                Object pathList = pathListField.get(classLoader);

                Field dexElementsField = pathList.getClass().getDeclaredField("dexElements");
                dexElementsField.setAccessible(true);
                Object[] dexElements = (Object[]) dexElementsField.get(pathList);

                for (Object element : dexElements) {
                    Field dexFileField = element.getClass().getDeclaredField("dexFile");
                    dexFileField.setAccessible(true);
                    Object dexFile = dexFileField.get(element);

                    if (dexFile != null) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            // Android 8.0 (API 26) e superior
                            Method getClassNamesMethod = dexFile.getClass().getDeclaredMethod("getClassNames");
                            //getClassNamesMethod.setAccessible(true);
                            List<String> classNames = (List<String>) getClassNamesMethod.invoke(dexFile);
                            if (classNames != null) {
                                loadedClasses.addAll(classNames);
                            }
                        } else {
                            // Android 7.1 (API 25) e inferior
                            Field mClassDefsField = dexFile.getClass().getDeclaredField("mClassDefs");
                            mClassDefsField.setAccessible(true);
                            Object classDefs = mClassDefsField.get(dexFile);

                            if (classDefs instanceof String[]) {
                                for (String className : (String[]) classDefs) {
                                    loadedClasses.add(className);
                                }
                            }
                        }
                    }
                }
            } else {printMe("GetClass: not an instance of BaseDex?!");}
        } catch (Exception e) {
            printMe("GetClass Err: "+e);
        }
        return loadedClasses;
    }


/*


    protected static Class getMainClass(XC_LoadPackage.LoadPackageParam lpparam) {
        final Class[] mainActivityClass = new Class[0];
        ApplicationInfo app=AndroidAppHelper.currentApplicationInfo();
        try{
            Class classobj =  XposedHelpers.findClass(app.className,lpparam.classLoader);
            Method[] methods = classobj.getDeclaredMethods();
            for (Method method : methods)
                if(method.getName().contains("onCreate") ) {
                    XposedBridge.hookMethod(method,new XC_MethodHook(){
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            mainActivityClass[0] = param.thisObject.getClass();
                        }
                    });
                    break;
                }
        } catch (XposedHelpers.ClassNotFoundError | java.lang.NoSuchMethodError e4) {  printMe("!Err: ",lpparam.packageName, e4.toString());}
        return mainActivityClass[0];
    }

    protected static <T> void printObject(T obj) {
        if (obj == null) {
            printMe("PrintObj: Null objt");
        } else if (obj.getClass().isArray()) {
            int length = Array.getLength(obj);
            printMe("PrintObj: Array of " + obj.getClass().getComponentType().getName() + " L:" + length);
            for (int i = 0; i < length; i++) {
                printMe(Array.get(obj, i).toString());
            }
        } else {
            printMe("PrintObj:",obj.toString());
        }
    }
     */

}
