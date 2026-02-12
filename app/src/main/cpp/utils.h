//
// Created by rougue on 10/03/2023.
//

#ifndef GASPARZINHO_UTILS_H
#define GASPARZINHO_UTILS_H
void printMe(const char * str,...);
int util_strcmp(const char *str);
char *package_name(int pid);
void package_name_reset(void);
void update_banlist(char **add, size_t add_len);
void push(struct Flist** head_ref, char* new_name);
void printMemoryBlock(const char *desc, void *addr, int len);
#endif //GASPARZINHO_UTILS_H
