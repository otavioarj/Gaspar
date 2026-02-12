//
// Created by rougue on 10/03/2023.
//
#include "gaspar.h"
//#include "libshook.h"

static char *cached_pkg_name = nullptr;

// Xposed scope functions
void printMe(const char *str, ...){
    va_list aptr;
    va_start(aptr, str);
    if (str[0] == '!' || is_debug) {
        char form[512];
        const char *name = cached_pkg_name ? cached_pkg_name : "Zygote";
        vsnprintf(form, sizeof(form), str, aptr);
        __android_log_print(ANDROID_LOG_WARN, TAG, "[%s:%d] - %s", name, getpid(), form);
    }
    va_end(aptr);
}

void printMemoryBlock(const char *desc, void *addr, int len) {
    char debug = is_debug;
    //Force print
    is_debug = 1;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;
    // each print line has 76 bytes per 16 bytes of data
    int ssize = (len < 16 ? 1 : len / 16) + 2;
    size_t total = 76 * ssize;
    char *obuff = (char*)malloc(total);
    if (!obuff) {
        is_debug = debug;
        return;
    }
    char *pos = obuff;

    // Output description if given.
    if (desc)
        pos += sprintf(pos, "%s:\n", desc);

    // Process every byte in the data.
    for (int i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                pos += sprintf(pos, "  %s\n", buff);
            // Output the offset.
            pos += sprintf(pos, "  %04x ", i);
        }

        // Now the hex code for the specific character.
        pos += sprintf(pos, " %02x", pc[i]);

        // And store a printable ASCII character for later.
        buff[i % 16] = (pc[i] < 0x20 || pc[i] > 0x7e) ? '.' : pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((len % 16) != 0) {
        pos += sprintf(pos, "   ");
        len++;
    }
    // And print the final ASCII bit.
    sprintf(pos, "  %s\n", buff);
    // %s to avoid format string vuln from hex data containing '%'
    printMe("!%s", obuff);
    free(obuff);
    is_debug = debug;
}

// Cached — resolved once per process. Reset after fork/specialize if needed.
char *package_name(int pid) {
    if (cached_pkg_name && !strstr(cached_pkg_name, "ygote"))
        return cached_pkg_name;

    char filename[64];
    snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    int fd = back_open(filename, O_RDONLY);
    if (fd < 0) {
        printMe("!pack name error");
        return nullptr;
    }
    FILE *file = fdopen(fd, "r");
    if (!file) {
        close(fd);
        return nullptr;
    }
    char cmdline[256];
    if (!fgets(cmdline, sizeof(cmdline), file)) {
        fclose(file);
        return nullptr;
    }
    fclose(file);

    free(cached_pkg_name);
    cached_pkg_name = strdup(cmdline);
    return cached_pkg_name;
}

void package_name_reset(void) {
    free(cached_pkg_name);
    cached_pkg_name = nullptr;
}

// Remove comment after mem audit
void update_banlist(char **add, size_t add_len) {
    char **newban = (char**)malloc((banlist.len + add_len) * sizeof(char*));
    if (!newban) {
        printMe("!update_banlist malloc fail");
        return;
    }
    memcpy(newban, banlist.jni_str_banned, banlist.len * sizeof(char*));
    for (size_t i = 0; i < add_len; i++)
        newban[banlist.len + i] = strdup(add[i]);
    free(banlist.jni_str_banned);
    banlist.jni_str_banned = newban;
    banlist.len += add_len;
}

int util_strcmp(const char *str) {
    //printMe("!Pack: %s",package_name(getpid()));
    for (int cnt = 0; cnt < (int)banlist.len; cnt++) {
        //printMe("!%s %s %d",str,banlist.jni_str_banned[cnt],cnt);
        if (strlen(banlist.jni_str_banned[cnt]) < 1) {
            printMe("!Util bug cnt=%d", cnt);
            return -1;
        }
// Seems weird, but nope. * at the start of a banned str means strictly equal, i.e.,
//  "Super" doesn't match with "su" (str_banned "*su"), but "su" match with "*su"
        if (banlist.jni_str_banned[cnt][0] == '*') {
            // skip the '*' for comparison
            if (strcmp(str, banlist.jni_str_banned[cnt] + 1) == 0) {
                printMe("MATCH: .%s. %s %d", banlist.jni_str_banned[cnt], str, cnt);
                return 1;
            }
        } else if (strcasestr(str, banlist.jni_str_banned[cnt])) {
            printMe("MATCH: .%s. %s %d", banlist.jni_str_banned[cnt], str, cnt);
            return 1;
        }
    }
    return 0;
}

void push(struct Flist** head_ref, char* new_name) {
    struct Flist* new_node = (struct Flist*)malloc(sizeof(struct Flist));
    new_node->fname = new_name;
    new_node->next = (*head_ref);
    (*head_ref) = new_node;
}
