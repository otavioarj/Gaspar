//
// Created by rougue on 10/03/2023.
//
#include "gaspar.h"



//https://android.googlesource.com/platform/bionic/+/466dbe4/libc/include/sys/system_properties.h

//__system_property_read_callback ++
size_t fake__system_property_get(const char *key, char *value) {
    if (!strcmp(key, "ro.build.tags")) {
        strcpy(value, "release-keys");
        printMe("!K SP: %s pass", key);
        return strlen(value);
    } else if (!strcmp(key, "ro.debuggable") || !strcmp(key, "service.adb.root")) {
        strcpy(value, "0");
        printMe("!K SP: %s pass", key);
        return 1;
    } else if (!strcmp(key, "ro.build.selinux") || !strcmp(key, "ro.secure")) {
        strcpy(value, "1");
        printMe("!K SP: %s pass", key);
        return 1;
    }

    size_t ret = back__system_property_get(key, value);
    printMe("K SP: %s Val: %s R:%d", key, value, ret);
    return ret;
}

//typedef int (*dl_iterate_phdr_t)(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data);
int hooked_callback(struct dl_phdr_info *info, size_t size, void *data) {
    if (info->dlpi_name && util_strcmp(info->dlpi_name)) {
        printMe("!Dl iterate: %s", info->dlpi_name);
        return 0;
    }
    int (*original_callback)(struct dl_phdr_info *, size_t, void *) =
        (int (*)(struct dl_phdr_info *, size_t, void *))data;
    return original_callback(info, size, data);
}

int fake_dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
    //int ret=back_dl_iterate_phdr(callback,data);
    Dl_info info;
    dladdr((void*)callback, &info);
    if (!strstr(info.dli_fname, "libart.so") && !strcmp(jni_name, "Zygote")) {
        printMe("Dl info: %s | %p", info.dli_fname, info.dli_fbase);
        return back_dl_iterate_phdr(hooked_callback, (void *)callback);
    }
    return back_dl_iterate_phdr(callback, data);
}

ssize_t fake_getxattr(const char *path, const char *name, void *value, size_t size) {
    ssize_t ret = back_getxattr(path, name, value, size);
    printMe("!K GXA: %s Val: %s R:%d", path, name, ret);
    return ret;

}

// This function populates the app dir with shadow files the app is opening
// i.e., /proc/pid/maps. Gaspar so far didn't control these files for removal
// — now tracked in Fnode and cleaned up in JNI_OnUnload.
char* fopen_shadown(const char *filename, int oflag) {
    const char *pkg = package_name(getpid());
    if (!pkg) return nullptr;

    size_t flen = strlen(filename);
    size_t plen = strlen(pkg);
    // "/data/data/" + pkg + "/_gaspar_" + pid(max10) + sanitized_filename + '\0'
    //strlen("/files/_gaspar") +PID
    size_t total = 11 + plen + 9 + 10 + flen + 1;
    char *file = (char*)malloc(total);
    if (!file) return nullptr;

    int offset = snprintf(file, total, "/data/data/%s/_gaspar_%d", pkg, getpid());
    for (size_t i = 0; i < flen; i++)
        file[offset + i] = (filename[i] == '/') ? '_' : filename[i];
    file[offset + flen] = '\0';

    //printMe("FShadow F: %s ", file);
//    if (back_access(file,F_OK )==0) {
//        return file;
//    }
    int stream_fd = back_open(filename, oflag, 0);
    int tmp_fd = back_open(file, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR);
    if (stream_fd < 0 || tmp_fd < 0) {
        printMe("!OShadow E: %s %d %d", file, stream_fd, tmp_fd);
        if (stream_fd >= 0) close(stream_fd);
        if (tmp_fd >= 0) close(tmp_fd);
        free(file);
        return nullptr;
    }

    FILE *stream = fdopen(stream_fd, "r");
    FILE *tmp = fdopen(tmp_fd, "w");
    char *line = nullptr;
    size_t len = 0;
    ssize_t nread;
    while ((nread = getline(&line, &len, stream)) != -1) {
        if (!util_strcmp(line))
            fwrite(line, (size_t)nread, 1, tmp);
    }
    free(line);
    fclose(tmp);
    fclose(stream);
    sync();
    // Fnode owns file for cleanup; caller gets a copy to free
    push(&Fnode, file);
    return strdup(file);
}

int fake_execve(const char *pathname, char *const argv[], char *const envp[]) {
// Avoid own package files in its own dir getting spammed here
    //if (!strcmp(pathname,jni_name))
    printMe("!execve: %s", pathname);
    if (util_strcmp(pathname)) {
        printMe("!execve block: %s", pathname);
        errno = EIO;
        return -1;
    }
    if (argv) {
        for (int a = 0; argv[a] != nullptr; a++) {
            if (util_strcmp(argv[a])) {
                printMe("!execve block argv: %s", argv[a]);
                errno = EIO;
                return -1;
            }
        }
    }
    return back_execve(pathname, argv, envp);
}

int fake_open(const char *pathname, int oflag, ...) {
    va_list vl;
    mode_t mode = 0;
    if (__open_modes_useful(oflag)) {
        va_start(vl, oflag);
        mode = (mode_t)va_arg(vl, int);
        va_end(vl);
    }

// Avoid own package files in its own dir getting spammed here
    //if (!strcmp(pathname,jni_name))
    printMe("open: %s", pathname);
    //printMe("!Pack %s",package_name(getpid()));
// TODO there are any cases to hook open at zygote? Any hook on zygote doesn't sustain on child app!
//  Cons: it can trigger magisk/frida/lsposed insertion on vmmaps
//  Pros: ??
    if (strstr(package_name(getpid()), "ygote") || strstr(jni_name, "Zygote"))
        return back_open(pathname, oflag, mode);

    if (strstr(pathname, "/proc/")) {
        char *ret = fopen_shadown(pathname, oflag);
        if (!ret) {
            errno = ENOENT;
            return -1;
        }
        int fd = back_open(ret, oflag, mode);
//        printMe("ret: %d %s",fd,ret);
        free(ret);
        return fd;
    } else if (util_strcmp(pathname)) {
        printMe("!open block: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return back_open(pathname, oflag, mode);
}

int fake_openat(int fd, const char *filepath, int oflag, ...) {
    va_list vl;
    mode_t mode = 0;
    if (__open_modes_useful(oflag)) {
        va_start(vl, oflag);
        mode = (mode_t)va_arg(vl, int);
        va_end(vl);
    }

    if (strstr(package_name(getpid()), "ygote") || strstr(jni_name, "Zygote"))
        return back_openat(fd, filepath, oflag, mode);

    if (strstr(filepath, "/proc/") && !strstr(filepath, "self/auxv")) {
        printMe("openat: %s", filepath);
        char *ret = fopen_shadown(filepath, oflag);
        if (!ret) {
            errno = ENOENT;
            return -1;
        }
        int fd2 = back_openat(fd, ret, oflag, mode);
        printMe("openat ret: %d %s", fd2, ret);
        free(ret);
        return fd2;
    } else if (util_strcmp(filepath)) {
        printMe("!openat block: %s", filepath);
        errno = ENOENT;
        return -1;
    }
    return back_openat(fd, filepath, oflag, mode);
}

/*
FILE *fake_fopen(const char *filename, const char *mode) {
    if(strstr(filename,"/proc/"))
    {
        printMe("fopenS: %s", filename);
        return back_fopen(fopen_shadown(filename,O_RDONLY),mode);
    }
    else if (util_strcmp(filename)) {
        printMe("fopen: %s", filename);
        errno=ENOENT;
        return nullptr;
    }
//    printMe("!fopen: %s", filename);
    return back_fopen(filename, mode);
}
 */

int fake_access(const char *pathname, int mode) {
    if (util_strcmp(pathname)) {
        printMe("!Access block: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    // Avoid own package files in its own dir getting spammed here
    //if (!strcmp(pathname,jni_name))
    printMe("Access: %s", pathname);
    return back_access(pathname, mode);
}

int fake_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (util_strcmp(pathname)) {
        printMe("!FAccess block: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    // Avoid own package files in its own dir getting spammed here
    //if (!strcmp(pathname,jni_name))
    printMe("FAccess: %s", pathname);
    return back_faccessat(dirfd, pathname, mode, flags);
}

FILE *fake_popen(const char *command, const char *type) {
    if (util_strcmp(command)) {
        printMe("!popen block: %s", command);
        errno = ENOENT;
        return nullptr;
    }
    printMe("popen: %s", command);
    return back_popen(command, type);
}

void *fake_memmem(const void *haystack, size_t haystacklen,
                  const void *needle, size_t needlelen) {
    if (util_strcmp((const char *)needle)) {
        printMe("!memmem block: %s", (const char *)needle);
        return nullptr;
    }
    printMe("memmem: %s", (const char *)needle);
    return back_memmem(haystack, haystacklen, needle, needlelen);
}

int fake_is_selinux_enabled() {
    return 1;
}

unsigned long fake_MS_Intune_Instru(unsigned int, unsigned int, char, char) {
    return 0;
}
