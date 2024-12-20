//
// Created by rougue on 10/03/2023.
//
#include "gaspar.h"



//https://android.googlesource.com/platform/bionic/+/466dbe4/libc/include/sys/system_properties.h

//__system_property_read_callback ++
size_t fake__system_property_get(const char *key,char* value){
    size_t ret=-1;
    if (!strcmp(key, "ro.build.tags")) {
        value = (char*)("release-keys");
        ret= strlen(value);
    } else if(!strcmp(key, "ro.debuggable") || !strcmp(key, "service.adb.root")){
         ret=0;
    } else if(!strcmp(key, "ro.build.selinux") || !strcmp(key, "ro.secure")){
        ret= 1;
    }

    if ((signed)ret>=0)
    {
        printMe("!K SP: %s pass", key);
        return ret;
    }
    ret=back__system_property_get(key, value);
    printMe("K SP: %s Val: %s R:%d", key, value, ret);
    return ret;
}

//typedef int (*dl_iterate_phdr_t)(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data);
int hooked_callback(struct dl_phdr_info *info, size_t size, void *data) {
    if (info->dlpi_name && util_strcmp(info->dlpi_name)){
        printMe("!Dl interate: %s",info->dlpi_name);
        return 0;
    }
    int (*original_callback)(struct dl_phdr_info *, size_t, void *) = (int (*)(struct dl_phdr_info *, size_t, void *))data;
    return original_callback(info, size, data);
}

int fake_dl_iterate_phdr(int (*callback)(struct dl_phdr_info *,size_t , void *),void *data){
    //int ret=back_dl_iterate_phdr(callback,data);
    Dl_info info;
    dladdr((void*)callback,&info);
    if (!strstr(info.dli_fname,"libart.so") && !strcmp(jni_name,"Zygote")) {
        printMe("Dl info: %s | %p\0",info.dli_fname,info.dli_fbase);
        return back_dl_iterate_phdr(hooked_callback,(void *)callback);
    }
    return back_dl_iterate_phdr(callback,data);
}

ssize_t fake_getxattr(const char *path, const char *name,void *value, size_t size){
    ssize_t ret = back_getxattr(path,name,value,size);
    printMe("!K GXA: %s Val: %s R:%d", path, name, ret);
    return ret;

}

char* fopen_shadown(const char *filename, int oflag){
    FILE *stream, *tmp;
    int stream_fd, tmp_fd;
    if (Fnode==nullptr)
        Fnode= (struct Flist*)malloc(sizeof(struct Flist));

    char *line = nullptr, *file= nullptr;
    const char *ftmp={"/data/data/"};
    size_t len = 0,cnt;
    ssize_t nread;

    file=(char*) malloc(strlen(filename) + strlen(ftmp) + strlen(package_name(getpid())) + 14+5);//strlen("/files/_gaspar") +PID);
    sprintf(file,"%s%s/_gaspar_%d",ftmp,package_name(getpid()),getpid());
    cnt=strlen(file);
    for (int cnt2=0;cnt2<strlen(filename);cnt++,cnt2++){
        if(filename[cnt2]=='/')
            file[cnt]='_';
        else
            file[cnt]=filename[cnt2];
    }
    file[cnt]='\0';
    //printMe("FShadow F: %s ", file);
//    if (back_access(file,F_OK )==0) {
//        return file;
//    }
    stream_fd= back_open(filename,oflag,0);
    tmp_fd= back_open(file,O_RDWR | O_CREAT, S_IWUSR |  S_IRUSR);
    if (stream_fd<0 || tmp_fd<0) {
        printMe("!OShadow E: %s %d %d", file, stream_fd,tmp_fd);
        free(file);
        return nullptr;
    }
    stream= fdopen(stream_fd,"r");
    tmp= fdopen(tmp_fd,"w");
    while ((nread = getline(&line, &len, stream)) != -1) {
        if (!util_strcmp(line))
            fwrite(line, static_cast<size_t>(nread), 1, tmp);
    }

    fclose(tmp);
//    free(line);
    fclose(stream);
    sync();
    push(&Fnode,file);
    return file;
}
int fake_execve(const char *pathname, char *const argv[],char *const  envp[]){
    char ret=0;
// Avoid own package files in its own dir getting spammed here
    //if (!strcmp(pathname,jni_name))
    printMe("!execve: %s",pathname);
    if(util_strcmp(pathname))
        ret= 1;
    else{
        int size= sizeof(*argv)/ sizeof(char*);
        for (int a=0;a<size;a++)
            if(util_strcmp(argv[a]))
                ret= 1;
    }
    if (!ret)
     return back_execve(pathname,argv,envp);
    else {
        printMe("!execve block: %s", pathname);
        errno=EIO;
        return -1;
    }
}

// This function populates the app dir with shadow files the app is opening
// i.e., /proc/pid/maps. Gaspar so far doesn't control this files later to removal
// so you have to clean it or wait until a elegant solution if made.
 int fake_open(const char *pathname, int oflag, ...){
    va_list vl;
    mode_t mode=0;
    char *ret;
    int fd;
    if(__open_modes_useful(oflag)) {
        va_start(vl, oflag);
        mode =(mode_t) va_arg(vl, int);
        va_end(vl);
    }
// Avoid own package files in its own dir getting spammed here
    //if (!strcmp(pathname,jni_name))
        printMe("open: %s", pathname);
    //printMe("!Pack %s",package_name(getpid()));
// TODO there are any cases to hook open at zygote? Any hook on zygote doesn't sustain on child app!
//  Cons: it can trigger magisk/frida/lsposed insertion on vmmaps
//  Pros: ??
    if(strstr(package_name(getpid()),"Zygote") || strstr(jni_name,"Zygote"))
    {
        printMe("open: Zygote bypass");
        return back_open(pathname,oflag,mode);
    }
    if(strstr(pathname,"/proc/") ) {
        ret = fopen_shadown(pathname, oflag);
        if (ret == nullptr) {
            errno=ENOENT;
            return -1;
        }
        fd=back_open((const char *)ret,oflag,mode);
//        printMe("ret: %d %s",fd,ret);
        free(ret);
        return fd;
    }
    else if (util_strcmp(pathname)) {
        printMe("!open: %s", pathname);
        errno=ENOENT;
        return -1;
    }
    return back_open(pathname,oflag,mode);
}

int fake_openat (int fd, const char* filepath, int oflag, ...){
    va_list vl;
    mode_t mode=0;
    char *ret;
    int fd2;

    if(__open_modes_useful(oflag)) {
        va_start(vl, oflag);
        mode =(mode_t) va_arg(vl, int);
        va_end(vl);
    }
    if(strstr(package_name(getpid()),"Zygote") || strstr(jni_name,"Zygote"))
    {
        printMe("openat: Zygote bypass");
        return back_openat(fd, filepath, oflag);
    }
    if(strstr(filepath,"/proc/") && strstr(filepath,"self/auxv")==nullptr)
    {
        printMe("openat: %s", filepath);
        ret=fopen_shadown(filepath,oflag);
        if(ret==nullptr)
            return -1;
        fd2 = back_openat(fd, (const char *) ret, oflag, mode);
        printMe(" ret: %d %s:",fd2,ret);
        free(ret);
        return fd2;
    }
    else if (util_strcmp(filepath)) {
        printMe("!openat: %s", filepath);
        errno=ENOENT;
        return -1;
    }
    return back_openat(fd, filepath, oflag);
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

int fake_access(const char *pathname, int mode){
    if (util_strcmp(pathname)) {
        printMe("!Access: %s", pathname);
        errno=ENOENT;
        return -1;
    }
    // Avoid own package files in its own dir getting spammed here
    //if (!strcmp(pathname,jni_name))
        printMe("Access: %s", pathname);
    return back_access(pathname, mode);
}

int fake_faccessat(int dirfd, const char *pathname, int mode, int flags){
    if (util_strcmp(pathname)) {
        printMe("!FAccess: %s", pathname);
        errno=ENOENT;
        return -1;
    }
    // Avoid own package files in its own dir getting spammed here
    //if (!strcmp(pathname,jni_name))
    printMe("FAccess: %s", pathname);
    return back_faccessat(dirfd,pathname,mode,flags);
}

FILE *fake_popen(const char *command, const char *type){
    if (util_strcmp(command)) {
        printMe("!popen: %s", command);
        errno=ENOENT;
        return nullptr;
    }
    printMe("popen: %s", command);
    return back_popen(command, type);
}

void * fake_memmem(const void *haystack, size_t haystacklen,const void *needle, size_t needlelen){
    if (util_strcmp((const char *)needle)) {
        printMe("!memmem: %s",(const char *)needle);
        return nullptr;
    }
    printMe("memmem: %s",(const char *)needle);
    return back_memmem(haystack,haystacklen,needle,needlelen);
}

int fake_is_selinux_enabled(){
    return 1;
}
unsigned long fake_MS_Intune_Instru (unsigned int ,unsigned int ,char ,char ){
    return 0;
}