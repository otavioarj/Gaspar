#include "gaspar.h"


/*
 * Not using as we already have JVM context in Gaspar :)
extern "C" [[gnu::visibility("default")]] [[gnu::used]]
jint JNI_OnLoad(JavaVM *jvm, void*) {
    JNIEnv *env = nullptr;
    jvm->GetEnv((void **)&env, JNI_VERSION_1_6);
    hook_func((void *)env->functions->FindClass, (void *)fake_FindClass, (void **)&backup_FindClass);
    return JNI_VERSION_1_6;
}

jclass (*backup_FindClass)(JNIEnv *env, const char *name);
jclass fake_FindClass(JNIEnv *env, const char *name)
{
    if(!strcmp(name, "dalvik/system/BaseDexClassLoader"))
        return nullptr;
    return backup_FindClass(env, name);
}
*/
size_t (*back__system_property_get)(const char *key, char *value);
//FILE *(*back_fopen)(const char *filename, const char *mode);
FILE *(*back_popen)(const char *command, const char *type);
void *(*back_memmem)(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
int (*back_access)(const char *pathname, int mode);
int (*back_open)(const char *__path, int __flags, ...);
int (*back_openat)(int __dir_fd, const char *__path, int __flags, ...);
ssize_t (*back_getxattr)(const char *, const char *, void *, size_t);
unsigned long (*back_MS_Intune_Instru)(unsigned int, unsigned int, char, char);
int (*back_dl_iterate_phdr)(int (*)(struct dl_phdr_info *, size_t, void *), void *);
int (*back_execve)(const char *, char *const [], char *const []);
int (*back_faccessat)(int dirfd, const char *pathname, int mode, int flags);
int (*back_is_selinux_enabled)(void);

char *jni_name = nullptr;
char is_debug;
char is_dl_iterate;
jni_ban banlist = {};
struct Flist *Fnode;

// *element marks as equal compare, i.e., to ban "su" not triggering the
//  match for instance in com.app.supercool by using "*su"
// "/su" matches every case of '*./su', while "*su" matches only "su".
const char *static_banned[] = {
    "magisk", "gaspar", "resetprop", "/su", "*su", "lsposed",
    "LSPHooker", "frida", "xposed", "busybox", "which",
    "mount", "getprop", "zygisk"
};

void on_library_loaded(const char *name, void *handle) {
// name appears to be null some times, even when handle is valid.
    void *target = nullptr;
    if (!handle) {
        printMe("!Dl: handle is null!");
        return;
    } else if (!name) {
        printMe("Dl: name is null!");
        return;
    }
    printMe("!DLoad %s", name);

    if (strcmp(name, "libselinux"))
        if ((target = dlsym(handle, "is_selinux_enabled")))
            hook_func(target, (void *)fake_is_selinux_enabled, (void **)&back_is_selinux_enabled);

    /*if ((target=dlsym(handle,"Java_com_microsoft_intune_mam_policy_InstrumentationCheck_instrumentationCheckFailed"))) {
        printMe("!MS_Intru");
        hook_func(target, (void *) fake_MS_Intune_Instru, (void **) &back_MS_Intune_Instru);
    }*/
    // Facetec removes dlsym name from the ELF header, cannot rely on name! Extra case to avoid re-hooking
    if (((target = dlsym(handle, "dl_iterate_phdr")) && target != (void*)back_dl_iterate_phdr) && !is_dl_iterate) {
        hook_func(target, (void *)fake_dl_iterate_phdr, (void **)&back_dl_iterate_phdr);
        //printMe("!dl_iterate_phdr");
        is_dl_iterate = 1;
    }
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    // Externs inits
    hook_func = entries->hook_func;
    Fnode = nullptr;
    //Max package name is 50, 64 to be page savvy
    jni_name = (char *)malloc(64);
    is_debug = 1;
    strcpy(jni_name, "Zygote");

    banlist.len = sizeof(static_banned) / sizeof(static_banned[0]);
    banlist.jni_str_banned = (char **)malloc(banlist.len * sizeof(char *));
    if (!banlist.jni_str_banned) {
        printMe("!Panic malloc Str BANNED! Brace for crash");
        return nullptr;
    }
    for (size_t i = 0; i < banlist.len; i++)
        //banlist.jni_str_banned[i] = (char *) malloc(sizeof(static_banned[i]));
        banlist.jni_str_banned[i] = strdup(static_banned[i]);
        //printMe("! %s . %s",banlist.jni_str_banned[i], static_banned[i]);

    // system hooks
    // TODO syscalls?
    //hook_func((void*) fopen, (void*) fake_fopen, (void**) &back_fopen);
    hook_func((void *)memmem, (void *)fake_memmem, (void **)&back_memmem);
    hook_func((void *)access, (void *)fake_access, (void **)&back_access);
    hook_func((void *)faccessat, (void *)fake_faccessat, (void **)&back_faccessat);
    hook_func((void *)popen, (void *)fake_popen, (void **)&back_popen);
    hook_func((void *)__system_property_get, (void *)fake__system_property_get, (void **)&back__system_property_get);
    hook_func((void *)__open_real, (void *)fake_open, (void **)&back_open);
    hook_func((void *)__openat_real, (void *)fake_openat, (void **)&back_openat);
    hook_func((void *)getxattr, (void *)fake_getxattr, (void **)&back_getxattr);
    hook_func((void *)execve, (void *)fake_execve, (void **)&back_execve);

    // Using ! to print this message, "!" is the tag for critical/essential messages on non debug build; is_debug=0
    printMe("!LibC Hooked Debug: %d", is_debug);
    return on_library_loaded;
}

// Android NDK scope

JNIEXPORT void JNICALL JNI_SetPackName(JNIEnv *env, jclass, jstring name) {
    const char *str = env->GetStringUTFChars(name, nullptr);
    strncpy(jni_name, str, 63);
    jni_name[63] = '\0';
    env->ReleaseStringUTFChars(name, str);
    // Invalidate cached package name so it re-resolves for this app
    package_name_reset();
}

// Dynamic alloc in heap with JNI while on xposed context can causes heap corruption
// on some memory monitor, as they tries to access global vars, but out of context
// this is why deny list is a global static :(
/*
JNIEXPORT void JNICALL JNI_SetDenyList(JNIEnv *env, jclass clazz, jstring denystr) {
    int size=env->GetArrayLength(reinterpret_cast<jarray>(denystr));
    jobject elem;
    banlist.len = sizeof(size) / sizeof(char*);
    banlist.jni_str_banned = (char **)malloc(banlist.len * sizeof(char*));
   /* for (size_t i = 0; i < banlist.len; i++) {
        banlist.jni_str_banned[i] = (char *) malloc(strlen(static_banned[i]));
        strcpy((char *const)(banlist.jni_str_banned[i]), (const char *)(static_banned[i]));
        //printMe("%s",jni_str_banned[i]);
    }
    for(int cnt=0;cnt<size;cnt++) {
        elem=env->GetObjectArrayElement(reinterpret_cast<jobjectArray>(denystr), cnt);
        banlist.jni_str_banned[cnt]= (char*)malloc(sizeof(elem));
        strcpy((char *const)(banlist.jni_str_banned[cnt]), env->GetStringUTFChars((jstring)elem, NULL));
    }
}*/

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;
    //size_t len = sizeof(static_banned) / sizeof(static_banned[0]);
    //jfieldID fid;
    jmethodID mid;
    jobjectArray denylist;
    jclass clazz;
    vm->GetEnv((void **)&env, JNI_VERSION_1_6);

    JNINativeMethod activityMethods[] = {
        {"JNI_SetPackName", "(Ljava/lang/String;)V", (void *)JNI_SetPackName}
//        {"JNI_SetDenyList", "(Ljava/lang/String;)V",(void*) JNI_SetDenyList}
    };
    clazz = env->FindClass("br/gasparzinho/Gaspar");
    env->RegisterNatives(clazz, activityMethods, sizeof(activityMethods) / sizeof(activityMethods[0]));
    mid = env->GetStaticMethodID(clazz, "update_denylist", "([Ljava/lang/String;)V");

    // denylist= static_cast<jobjectArray>(env->GetStaticObjectField(clazz, fid));
    denylist = env->NewObjectArray((jsize)banlist.len, env->FindClass("java/lang/String"), nullptr);
    for (int cnt = 0; cnt < (int)banlist.len; cnt++)
        env->SetObjectArrayElement(denylist, cnt, env->NewStringUTF(banlist.jni_str_banned[cnt]));
    env->CallStaticVoidMethod(clazz, mid, denylist);

    return JNI_VERSION_1_6;
}

// REMOVES files created? — Yes, cleanup shadow files and free resources :)
void JNI_OnUnload(JavaVM *vm, void *reserved) {
    printMe("!Unload!");
    for (size_t i = 0; i < banlist.len; i++)
        free(banlist.jni_str_banned[i]);
    free(banlist.jni_str_banned);
    banlist.jni_str_banned = nullptr;
    banlist.len = 0;

    free(jni_name);
    jni_name = nullptr;
    package_name_reset();

    while (Fnode) {
        //printMe("Rem: %d",remove(Fnode->fname));
        // Remove the file :)
        remove(Fnode->fname);
        free(Fnode->fname);
        struct Flist *cur = Fnode;
        Fnode = Fnode->next;
        free(cur);
    }
}
