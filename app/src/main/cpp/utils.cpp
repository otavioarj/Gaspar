//
// Created by rougue on 10/03/2023.
//
#include "gaspar.h"
//#include "libshook.h"


// Xposed scope functions
void printMe(const char * str,...){
    char *form, *name;
    va_list aptr;
    va_start(aptr, str);
    if (str[0] =='!' || is_debug) {
        form = (char *) malloc(strlen(jni_name) + 4096);

        if (strcmp(jni_name,"Zygote"))
            name=package_name(getpid());
        else
            name=strdup("Zygote");
        if(form==NULL)
        {
            __android_log_print(ANDROID_LOG_WARN, TAG, "[%s:%d] PrintMe no memory?!", name,getpid());
            va_end(aptr);
            return;
        }

        vsprintf(form, str, aptr);
        __android_log_print(ANDROID_LOG_WARN, TAG, "[%s:%d] - %s", name,getpid(), form);
        free(form);
    }
    va_end(aptr);
}

void printMemoryBlock(const char *desc, void *addr, int len) {
    char debug=is_debug;
    //Force print
    is_debug=1;
    int i,ssize;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;
    // each print line has 76 bytes per 16 bytes of data
    ssize= len<16?1:len/16;
    char * obuff= (char *)(malloc(static_cast<size_t>(76 * (ssize))));
    char * buff2= (char *)malloc(20);

    // Output description if given.
    if (desc != NULL)
        sprintf (obuff,"%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) {
                sprintf(buff2, "  %s\n", buff);
                strcat(obuff,buff2);
            }
            // Output the offset.
            sprintf(buff2,"  %04x ", i);
            strcat(obuff,buff2);
        }

        // Now the hex code for the specific character.
        sprintf(buff2," %02x", pc[i]);
        strcat(obuff,buff2);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        strcat(obuff,"   ");
        i++;
    }
    // And print the final ASCII bit.
    sprintf(buff2,"  %s\n", buff);
    strcat(obuff,buff2);
    printMe(obuff);
    free(obuff);
    free(buff2);
    is_debug=debug;
}


// Remove comment after mem audit
void update_banlist(char ** add){
     char **newban;
     size_t len= malloc_usable_size(add)/sizeof(char*);
     size_t len2= banlist.len - 1;
     newban= (char**) malloc((banlist.len+len)*sizeof(char*));
     memcpy(newban,banlist.jni_str_banned,banlist.len*sizeof(char*));
    for (size_t i = 0; i < len; i++) {
         newban[len2+i] = (char *) malloc(strlen(add[i]));
         strcpy(newban[i], (const char *) (add[i]));
    }
    free(banlist.jni_str_banned);
    banlist.jni_str_banned=newban;
    banlist.len+=len;
}

char *  package_name(int pid) {
    char filename[256];
    char *name;
    size_t size=0;
    snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    FILE *file = fdopen(back_open(filename,O_RDONLY),"r");
    if (file == nullptr) {
        printMe("pack name error");
        return nullptr;
    }
    char cmdline[256];
    fgets(cmdline, sizeof(cmdline), file);
    fclose(file);
    size=strlen(cmdline);
    name=(char*) malloc(size);
    strcpy(name,cmdline);
    return name;
}


int util_strcmp(const char *str){
    //printMe("!Pack: %s",package_name(getpid()));
    char got=0;
    for (int cnt=0;cnt<banlist.len; cnt++) {
        //printMe("!%s %s %d",str,banlist.jni_str_banned[cnt],cnt);
        if (strlen(banlist.jni_str_banned[cnt])<1)
        {
            printMe("!Util bug cnt=%d",cnt);
            return -1;
         }
// Seems weird, but nope. * at the start of a banned str means strictly equal, i.e.,
//  "Super" doesn't mat with "su" (str_banned "*su"), but "su" match with "*su"
        if(banlist.jni_str_banned[cnt][0]=='*' && strcmp(str,banlist.jni_str_banned[cnt])==0)
            got=1;
        else if (strcasestr(str,  banlist.jni_str_banned[cnt]))
            got=1;
        if (got){
            printMe("MATCH: .%s. %s %d", banlist.jni_str_banned[cnt],str,cnt);
            return 1;
        }
    }
    return 0;
}

void push(struct Flist** head_ref, char* new_name)
{
    struct Flist* new_node= (struct Flist*)malloc(sizeof(struct Flist));
    new_node->fname = new_name;
    new_node->next = (*head_ref);
    (*head_ref) = new_node;
}