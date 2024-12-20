package br.gasparzinho;

import android.annotation.SuppressLint;

import java.lang.reflect.Method;
import java.util.ArrayList;
//import java.lang.reflect.Modifier;
//import javax.net.ssl.HostnameVerifier;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class TLS extends Gaspar {

    protected static void doTrustManagerImpl(Object param ) throws Exception{
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        try {
                @SuppressLint("PrivateApi") Class classobj = Class.forName("com.android.org.conscrypt.TrustManagerImpl");
                Method[] methods = classobj.getDeclaredMethods();
                for (Method method : methods) {
                    if(Mycompare(method.getName(),"setDefaultHostnameVerifier") || Mycompare(method.getName(),"setHostnameVerifier") ) {
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                return;
                            }
                        });
                    }
                    else if (Mycompare(method.getName(),"checkTrustedRecursive")) {
                        XposedBridge.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                ArrayList array = new ArrayList();
                                param.setResult(array);
                            }
                        });
                        break;
                    }
                }
            } catch (ClassNotFoundException |java.lang.NoSuchMethodError e) {  printMe("!Err: ",lpparam.packageName, e.toString());
        } catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }
    }

    protected static void doHttpsURLConnection(Object param ) throws Exception{
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        try {

            @SuppressLint("PrivateApi") Class classobj = Class.forName("javax.net.ssl.HttpsURLConnection");
            Method[] methods = classobj.getDeclaredMethods();
            for (Method method : methods)
                if(Mycompare(method.getName(),"setDefaultHostnameVerifier") || Mycompare(method.getName(),"setSSLSocketFactory")
                        || Mycompare(method.getName(),"setHostnameVerifier") ) {
                    XposedBridge.hookMethod(method,new XC_MethodHook(){
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            return;
                        }
                    });
                    break;
                }
        } catch (ClassNotFoundException | java.lang.NoSuchMethodError e) {  printMe("!Err: ",lpparam.packageName, e.toString());
        } catch (Exception e) {
            printMe("Trows: ", e.getLocalizedMessage());
            throw e;
        }

    }
    
    protected static void doOkHttp(Object param ) throws Exception{
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        String okhttp []={"com.android.okhttp","okhttp3","com.squareup.okhttp"};
        String okhttpN="";
        for ( String name :okhttp) {
            try {
                  Class.forName(name+".Call");
                  okhttpN=name;
                  break;
                } catch (ClassNotFoundException  e) { continue;}
        }
        try {
            @SuppressLint("PrivateApi") Class classobj = Class.forName(okhttpN+".internal.tls.OkHostnameVerifier");
            Method[] methods = classobj.getDeclaredMethods();
            for (Method method : methods)
                if(Mycompare(method.getName(),"verify")) {
                    XposedBridge.hookMethod(method,new XC_MethodHook(){
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            param.setResult(Boolean.TRUE);
                        }
                    });
                    break;
                }
            classobj = Class.forName(okhttpN+".CertificatePinner");
            methods = classobj.getDeclaredMethods();
            for (Method method : methods)
                if(Mycontains(method.getName(),"check")) {
                    XposedBridge.hookMethod(method,new XC_MethodHook(){
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if(method.getName().equals("check") )
                                param.setResult(Boolean.TRUE);
                        }
                    });
                    break;
                }
        } catch (ClassNotFoundException |java.lang.NoSuchMethodError e4) {
            printMe("!Err: ", lpparam.packageName, e4.toString());
        } catch (Exception e) {
                printMe("Trows: ", e.getLocalizedMessage());
                throw e;
        }
    }
/*
    protected static void doMassVerifier(Object param ) {
        XC_LoadPackage.LoadPackageParam lpparam = (XC_LoadPackage.LoadPackageParam) param;
        XposedHelpers.findAndHookMethod("o.ڒ", lpparam.classLoader, "verify", java.lang.String.class, javax.net.ssl.SSLSession.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                param.setResult(true);
            }
        });

        XposedHelpers.findAndHookMethod("o.ｹ", lpparam.classLoader, "verify", java.lang.String.class, javax.net.ssl.SSLSession.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                param.setResult(true);
            }
        });

        XposedHelpers.findAndHookMethod("o.דּ", lpparam.classLoader, "verify", java.lang.String.class, javax.net.ssl.SSLSession.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                param.setResult(true);
            }

        });

    }*/

}

