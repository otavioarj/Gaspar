package br.gasparzinho;

import net.bytebuddy.ByteBuddy;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.ClassVisitor;
import java.io.FileOutputStream;
import java.io.IOException;
import de.robv.android.xposed.XposedHelpers;
import android.content.Context;

public class Decomp extends Gaspar{

    protected static void decompile(ClassLoader loader, String className, String methodName, boolean infinite) {

        // Load the class and get the bytecode
        Class<?> targetClass = null;
        int cnt=0;
        while (targetClass == null) {
            if (cnt==4 && !infinite){
                printMe("Giving up Class "+className);
                return;
            }
            try {
                targetClass = XposedHelpers.findClass(className,loader);//Class.forName(className);
            } catch (XposedHelpers.ClassNotFoundError e) {
                printMe("Decomp Err: Class '" + className + "' not found. Retrying in 15 seconds...");
                cnt++;
                try {
                    Thread.sleep(15000);
                } catch (InterruptedException ie) {
                    printMe("Decomp Err: Interrupted while waiting to retry class loading.");
                }
            } catch (Exception e) {
                printMe("DecompErr: " + e.getMessage());
                return;
            }
        }

        // Get the bytecode of the target class using ByteBuddy
        byte[] classBytes = null;
        try {
            classBytes = new ByteBuddy()
                    .redefine(targetClass)
                    .make()
                    .getBytes();
        } catch (Exception e) {
            printMe("Decomp Err: generating bytecode for class " + className + ": " + e.getMessage());
            return;
        }

        // Extract the method bytecode using ASM
        ClassReader classReader = null;
        ClassWriter classWriter = null;
        try {
            classReader = new ClassReader(classBytes);
            classWriter = new ClassWriter(classReader, 0);
            classReader.accept(new ClassVisitor(Opcodes.ASM9, classWriter) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                    printMe("Decomp: visiting: "+name);
                    if (name.equals(methodName)) {
                        return new MethodVisitor(Opcodes.ASM9) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                printMe("Bytecode of method " + name + " is being written.");
                            }
                        };
                    }
                    return super.visitMethod(access, name, descriptor, signature, exceptions);
                }
            }, 0);
        } catch (Exception e) {
            printMe("Error processing bytecode of class: " + e.getMessage());
            return;
        }

        byte[] bytecode = null;
        try {
            bytecode = classWriter.toByteArray();
        } catch (Exception e) {
            printMe("Error generating final bytecode with ASM: " + e.getMessage());
            return;
        }

        // Define the path where the file will be saved
        String path = "/data/local/tmp/" + className + "." + methodName + ".class";

        // Write the bytecode to the file
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(bytecode);
        } catch (IOException e) {
            printMe("!Err: Error writing bytecode file: " + e.getLocalizedMessage());
            return;
        } catch (Exception e) {
            printMe("Throws: Unexpected error while saving file: " + e.getLocalizedMessage());
            return;
        }

    }

}