//
// Created by rougue on 20/01/2023.
//

#ifndef GASPARZINHO_GASPAR_H
#define GASPARZINHO_GASPAR_H
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/xattr.h>
#include <android/log.h>
#include <jni.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <malloc.h>
#include "stdio_ext.h"
#include "libshook.h"
#include "utils.h"
#define __open_modes_useful(flags) (((flags) & O_CREAT) || ((flags) & O_TMPFILE) == O_TMPFILE)
#define TAG "[Gaspar]"

struct Flist{
    char *fname;
    Flist *next;
};
extern struct Flist* Fnode;

typedef int (*HookFunType)(void *func, void *replace, void **backup);
typedef int (*UnhookFunType)(void *func);
typedef void (*NativeOnModuleLoaded)(const char *name, void *handle);
typedef struct {
    uint32_t version;
    HookFunType hook_func;
    UnhookFunType unhook_func;
} NativeAPIEntries;
typedef NativeOnModuleLoaded (*NativeInit)(const NativeAPIEntries *entries);
static HookFunType hook_func = nullptr;

extern char *jni_name;
extern char is_debug;
extern char is_dl_iterate;

struct jni_ban {
    char **jni_str_banned;
    size_t len;
};
extern const char *static_banned[];
extern jni_ban banlist;

#endif //GASPARZINHO_GASPAR_H
