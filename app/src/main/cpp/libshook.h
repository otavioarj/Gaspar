//
// Created by rougue on 10/03/2023.
//
#ifndef GASPARZINHO_LIBSHOOK_H
#define GASPARZINHO_LIBSHOOK_H

int fake_access(const char *pathname, int mode);
int fake_faccessat(int dirfd, const char *pathname, int mode, int flags);
int fake_open(const char* __path, int __flags,  ...);
int fake_openat (int __dir_fd, const char* __path, int __flags, ...);
ssize_t fake_getxattr(const char *, const char *, void* , size_t );
int fake_dl_iterate_phdr(int (*)(struct dl_phdr_info *,size_t , void *),void *);
//FILE* fake_fopen(const char *filename, const char *mode);
void* fake_memmem(const void *, size_t ,const void *, size_t );
int fake_memcmp ( const void * ptr1, const void * ptr2, size_t num );
FILE *fake_popen(const char *, const char *);
size_t fake__system_property_get(const char *,char* );
unsigned long fake_MS_Intune_Instru (unsigned int ,unsigned int ,char ,char );
int fake_execve(const char *, char *const  [],char *const  []);
int fake_is_selinux_enabled(void);
extern int (*back_execve)(const char *, char *const  [],char *const []);
extern size_t (*back__system_property_get)(const char *,char* );
//extern FILE *(*back_fopen)(const char *filename, const char *mode);
extern FILE *(*back_popen)(const char *, const char *);
extern void * (*back_memmem)(const void *, size_t ,const void *, size_t );
extern int (*back_memcmp) ( const void * ptr1, const void * ptr2, size_t num );
extern int (*back_access)(const char *pathname, int mode);
extern int (*back_faccessat)(int dirfd, const char *pathname, int mode, int flags);
extern int (*back_open)(const char* __path, int __flags,  ...);
extern int (*back_openat) (int __dir_fd, const char* __path, int __flags, ...);
extern ssize_t (*back_getxattr)(const char *, const char *, void* , size_t );
extern int (*back_dl_iterate_phdr)(int (*)(struct dl_phdr_info *,size_t , void *),void *);
extern unsigned long (*back_MS_Intune_Instru) (unsigned int ,unsigned int ,char ,char );
extern int (*back_is_selinux_enabled)(void);
#endif //GASPARZINHO_LIBSHOOK_H
