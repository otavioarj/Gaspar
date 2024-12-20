package br.gasparzinho;

import static br.gasparzinho.Gaspar.printMe;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
/*import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;*/
import java.util.function.Consumer;

public class Runs extends Thread {
    static XC_LoadPackage.LoadPackageParam param;

    public Runs(XC_LoadPackage.LoadPackageParam lpparam) {
        this.param = lpparam;
    }

    @FunctionalInterface
    public interface ThrowingConsumer<T> {
        void accept(T t) throws Exception;
    }

    protected void exec(ThrowingConsumer<Object> methodRef) throws Exception {
        new Thread(() -> {
            try {
                methodRef.accept((Object) param);
            } catch (IllegalArgumentException e) {
                printMe(param.packageName, e.toString());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).start();
    }

    protected void exec(Runnable methodRef) throws Exception {
        new Thread(() -> {
            try {
                methodRef.run();
            } catch (IllegalArgumentException e) {
                printMe(param.packageName, e.toString());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).start();
    }
}




