/* inih -- simple .INI file parser

SPDX-License-Identifier: BSD-3-Clause

Copyright (C) 2009-2020, Ben Hoyt

inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info:

https://github.com/benhoyt/inih

*/
static const char *TAG = "Ini parse";

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>  // <cstdlib> en C++
#include "ini.h"

#if !INI_USE_STACK
#if INI_CUSTOM_ALLOCATOR
#include <stddef.h>
void* ini_malloc(size_t size);
void ini_free(void* ptr);
void* ini_realloc(void* ptr, size_t size);
#else
#include <stdlib.h>
#define ini_malloc malloc
#define ini_free free
#define ini_realloc realloc
#endif
#endif

#define MAX_SECTION 50
#define MAX_NAME 50

/* Used by ini_parse_string() to keep track of string parsing state. */
typedef struct {
    const char* ptr;
    size_t num_left;
} ini_parse_string_ctx;

/* Strip whitespace chars off end of given string, in place. Return s. */
static char* rstrip(char* s)
{
    char* p = s + strlen(s);
    while (p > s && isspace((unsigned char)(*--p)))
        *p = '\0';
    return s;
}

/* Return pointer to first non-whitespace char in given string. */
static char* lskip(const char* s)
{
    while (*s && isspace((unsigned char)(*s)))
        s++;
    return (char*)s;
}

/* Return pointer to first char (of chars) or inline comment in given string,
   or pointer to NUL at end of string if neither found. Inline comment must
   be prefixed by a whitespace character to register as a comment. */
static char* find_chars_or_comment(const char* s, const char* chars)
{
#if INI_ALLOW_INLINE_COMMENTS
    int was_space = 0;
    while (*s && (!chars || !strchr(chars, *s)) &&
           !(was_space && strchr(INI_INLINE_COMMENT_PREFIXES, *s))) {
        was_space = isspace((unsigned char)(*s));
        s++;
    }
#else
    while (*s && (!chars || !strchr(chars, *s))) {
        s++;
    }
#endif
    return (char*)s;
}

/* Similar to strncpy, but ensures dest (size bytes) is
   NUL-terminated, and doesn't pad with NULs. */
static char* strncpy0(char* dest, const char* src, size_t size)
{
    /* Could use strncpy internally, but it causes gcc warnings (see issue #91) */
    size_t i;
    for (i = 0; i < size - 1 && src[i]; i++)
        dest[i] = src[i];
    dest[i] = '\0';
    return dest;
}

/* See documentation in header file. */
int ini_parse_stream(ini_reader reader, void* stream, ini_handler handler,
                     void* user)
{
    /* Uses a fair bit of stack (use heap instead if you need to) */
#if INI_USE_STACK
    char line[INI_MAX_LINE];
    size_t max_line = INI_MAX_LINE;
#else
    char* line;
    size_t max_line = INI_INITIAL_ALLOC;
#endif
#if INI_ALLOW_REALLOC && !INI_USE_STACK
    char* new_line;
    size_t offset;
#endif
    char section[MAX_SECTION] = "";
    char prev_name[MAX_NAME] = "";

    char* start;
    char* end;
    char* name;
    char* value;
    int lineno = 0;
    int error = 0;

#if !INI_USE_STACK
    line = (char*)ini_malloc(INI_INITIAL_ALLOC);
    if (!line) {
        return -2;
    }
#endif

#if INI_HANDLER_LINENO
#define HANDLER(u, s, n, v) handler(u, s, n, v, lineno)
#else
#define HANDLER(u, s, n, v) handler(u, s, n, v)
#endif

    /* Scan through stream line by line */
    while (reader(line, (int)max_line, stream) != NULL) {
#if INI_ALLOW_REALLOC && !INI_USE_STACK
        offset = strlen(line);
        while (offset == max_line - 1 && line[offset - 1] != '\n') {
            max_line *= 2;
            if (max_line > INI_MAX_LINE)
                max_line = INI_MAX_LINE;
            new_line = ini_realloc(line, max_line);
            if (!new_line) {
                ini_free(line);
                return -2;
            }
            line = new_line;
            if (reader(line + offset, (int)(max_line - offset), stream) == NULL)
                break;
            if (max_line >= INI_MAX_LINE)
                break;
            offset += strlen(line + offset);
        }
#endif

        lineno++;

        start = line;
#if INI_ALLOW_BOM
        if (lineno == 1 && (unsigned char)start[0] == 0xEF &&
                           (unsigned char)start[1] == 0xBB &&
                           (unsigned char)start[2] == 0xBF) {
            start += 3;
        }
#endif
        start = lskip(rstrip(start));

        if (strchr(INI_START_COMMENT_PREFIXES, *start)) {
            /* Start-of-line comment */
        }
#if INI_ALLOW_MULTILINE
        else if (*prev_name && *start && start > line) {
#if INI_ALLOW_INLINE_COMMENTS
            end = find_chars_or_comment(start, NULL);
            if (*end)
                *end = '\0';
            rstrip(start);
#endif
            /* Non-blank line with leading whitespace, treat as continuation
               of previous name's value (as per Python configparser). */
            if (!HANDLER(user, section, prev_name, start) && !error)
                error = lineno;
        }
#endif
        else if (*start == '[') {
            /* A "[section]" line */
            end = find_chars_or_comment(start + 1, "]");
            if (*end == ']') {
                *end = '\0';
                strncpy0(section, start + 1, sizeof(section));
                *prev_name = '\0';
#if INI_CALL_HANDLER_ON_NEW_SECTION
                if (!HANDLER(user, section, NULL, NULL) && !error)
                    error = lineno;
#endif
            }
            else if (!error) {
                /* No ']' found on section line */
                error = lineno;
            }
        }
        else if (*start) {
            /* Not a comment, must be a name[=:]value pair */
            end = find_chars_or_comment(start, "=:");
            if (*end == '=' || *end == ':') {
                *end = '\0';
                name = rstrip(start);
                value = end + 1;
#if INI_ALLOW_INLINE_COMMENTS
                end = find_chars_or_comment(value, NULL);
                if (*end)
                    *end = '\0';
#endif
                value = lskip(value);
                rstrip(value);

                /* Valid name[=:]value pair found, call handler */
                strncpy0(prev_name, name, sizeof(prev_name));
                if (!HANDLER(user, section, name, value) && !error)
                    error = lineno;
            }
            else if (!error) {
                /* No '=' or ':' found on name[=:]value line */
#if INI_ALLOW_NO_VALUE
                *end = '\0';
                name = rstrip(start);
                if (!HANDLER(user, section, name, NULL) && !error)
                    error = lineno;
#else
                error = lineno;
#endif
            }
        }

#if INI_STOP_ON_FIRST_ERROR
        if (error)
            break;
#endif
    }

#if !INI_USE_STACK
    ini_free(line);
#endif

    return error;
}

/* See documentation in header file. */
int ini_parse_file(FILE* file, ini_handler handler, void* user)
{
    return ini_parse_stream((ini_reader)fgets, file, handler, user);
}

/* See documentation in header file. */
int ini_parse(const char* filename, ini_handler handler, void* user)
{
    FILE* file;
    int error;

    file = fopen(filename, "r");
    if (!file)
        return -1;
    error = ini_parse_file(file, handler, user);
    fclose(file);
    return error;
}

/* An ini_reader function to read the next line from a string buffer. This
   is the fgets() equivalent used by ini_parse_string(). */
static char* ini_reader_string(char* str, int num, void* stream) {
    ini_parse_string_ctx* ctx = (ini_parse_string_ctx*)stream;
    const char* ctx_ptr = ctx->ptr;
    size_t ctx_num_left = ctx->num_left;
    char* strp = str;
    char c;

    if (ctx_num_left == 0 || num < 2)
        return NULL;

    while (num > 1 && ctx_num_left != 0) {
        c = *ctx_ptr++;
        ctx_num_left--;
        *strp++ = c;
        if (c == '\n')
            break;
        num--;
    }

    *strp = '\0';
    ctx->ptr = ctx_ptr;
    ctx->num_left = ctx_num_left;
    return str;
}

/* See documentation in header file. */
int ini_parse_string(const char* string, ini_handler handler, void* user) {
    ini_parse_string_ctx ctx;

    ctx.ptr = string;
    ctx.num_left = strlen(string);
    return ini_parse_stream((ini_reader)ini_reader_string, &ctx, handler,
                            user);
}

char *join(char *str_1, char *str_2)
{
    char *result=NULL;

    if(!str_1)
    {
        result = malloc(strlen(str_2) + 1);
        sprintf(result, "%s", str_2);
    }
    else if(!str_2)
    {
        result = malloc(strlen(str_1) + 1);
        sprintf(result, "%s", str_1);
    }
    else
    {
        result = malloc(strlen(str_1) + strlen(str_2) + 1);
        sprintf(result, "%s%s", str_1, str_2);
    }

    return result;
}


int parse(void *user, const char *section, const char *name, const char *value)
{
    config_values_t *pconfig = (config_values_t *)user;
    char *set = "SETTINGS";

    if (MATCH(set, "SECURE_CERT_PATH"))
        pconfig->SECURE_CERT_PATH = strdup(value);
    else if (MATCH(set, "DEVICE_CERT"))
        pconfig->DEVICE_CERT = strdup(value);
    else if (MATCH(set, "SECURE_KEY"))
        pconfig->SECURE_KEY = strdup(value);
    else if (MATCH(set, "INES_TEMPLATE_ID"))
        pconfig->INES_TEMPLATE_ID = strdup(value);
    else if (MATCH(set, "INES_ORG_ID"))
        pconfig->INES_ORG_ID = strdup(value);
    else if (MATCH(set, "AWS_IOT_ENDPOINT"))
        pconfig->AWS_IOT_ENDPOINT = strdup(value);
    else if (MATCH(set, "AZURE_DPS_GLOBAL_DEVICE_ENDPOINT"))
        pconfig->AZURE_DPS_GLOBAL_DEVICE_ENDPOINT = strdup(value);
    else if (MATCH(set, "AZURE_DPS_ID_SCOPE"))
        pconfig->AZURE_DPS_ID_SCOPE = strdup(value);
    else if (MATCH(set, "DEVICE_NAME_PREFIX"))
        pconfig->DEVICE_NAME_PREFIX = strdup(value);
    else if (MATCH(set, "DEVICE_SERIAL_NUMBER"))
        pconfig->DEVICE_SERIAL_NUMBER = strdup(value);
    else if (MATCH(set, "DEVICE_COUNTRY"))
        pconfig->DEVICE_COUNTRY = strdup(value);
    else if (MATCH(set, "PROTOCOL"))
        pconfig->PROTOCOL = strdup(value);
    else if (MATCH(set, "FACTORY_CERT"))
        pconfig->FACTORY_CERT = strdup(value);
    else if (MATCH(set, "FACTORY_KEY"))
        pconfig->FACTORY_KEY = strdup(value);
    else if (MATCH(set, "INES_EST_SERVER_URL"))
        pconfig->INES_EST_SERVER_URL = strdup(value);
    else if (MATCH(set, "INES_REST_SERVER_URL"))
        pconfig->INES_REST_SERVER_URL = strdup(value);
    else if (MATCH(set, "CLIENT_CERT"))
        pconfig->CLIENT_CERT = strdup(value);
    else if (MATCH(set, "CLIENT_KEY"))
        pconfig->CLIENT_KEY = strdup(value);
    else if (MATCH(set, "USE_VAULTIC"))
        pconfig->USE_VAULTIC = strdup(value);
    else
        return 1;
    return 0;
}

int parseConfigFile(char* pathToFile, config_values_t*handler){

    int ret;

    ret = ini_parse(pathToFile, parse, handler);

    if(ret<0){
        return ret;
    }
    
    /*if(verifyConfigStruc(handler)!=0)
        return -1;*/
        
    if(handler->DEVICE_CERT)
        if (strlen(handler->DEVICE_CERT)<1)
            handler->DEVICE_CERT_PATH = NULL;
        else
            handler->DEVICE_CERT_PATH = join(handler->SECURE_CERT_PATH, handler->DEVICE_CERT);
    else
        handler->DEVICE_CERT_PATH = NULL;

    if(handler->CLIENT_CERT)
        if (strlen(handler->CLIENT_CERT)<1)
            handler->CLIENT_CERT_PATH = NULL;
        else
            handler->CLIENT_CERT_PATH = join(handler->SECURE_CERT_PATH, handler->CLIENT_CERT);
    else
        handler->CLIENT_CERT_PATH = NULL;

    if(handler->CLIENT_KEY)
        if (strlen(handler->CLIENT_KEY)<1)
            handler->CLIENT_KEY_PATH = NULL;
        else
            handler->CLIENT_KEY_PATH = join(handler->SECURE_CERT_PATH, handler->CLIENT_KEY);
    else
        handler->CLIENT_KEY_PATH = NULL;
    
    if(handler->FACTORY_CERT)
        if (strlen(handler->FACTORY_CERT)<1)
            handler->FACTORY_CERT_PATH = NULL;
        else
            handler->FACTORY_CERT_PATH = join(handler->SECURE_CERT_PATH, handler->FACTORY_CERT);
    else
        handler->FACTORY_CERT_PATH = NULL;

    if(handler->FACTORY_KEY)
        if (strlen(handler->FACTORY_KEY)<1)
            handler->FACTORY_KEY_PATH = NULL;
        else
            handler->FACTORY_KEY_PATH = join(handler->SECURE_CERT_PATH, handler->FACTORY_KEY);
    else
        handler->FACTORY_KEY_PATH = NULL;

    if(handler->SECURE_KEY)
        if (strlen(handler->SECURE_KEY)<1)
            handler->SECURE_KEY_PATH = NULL;
        else
            handler->SECURE_KEY_PATH = join(handler->SECURE_CERT_PATH, handler->SECURE_KEY);
    else
        handler->SECURE_KEY_PATH = NULL;

    if(handler->AWS_IOT_ENDPOINT)
        if (strlen(handler->AWS_IOT_ENDPOINT)<1)
            handler->AWS_MQTT_ENDPOINT_URI = NULL;
        else
            handler->AWS_MQTT_ENDPOINT_URI = join("mqtts://", handler->AWS_IOT_ENDPOINT);
    else
        handler->AWS_MQTT_ENDPOINT_URI = NULL;

    return 0;
}

int initConfigFile(config_values_t*handler){

    int ret;
    handler->SECURE_CERT_PATH = NULL;
    handler->DEVICE_CERT = NULL;
    handler->SECURE_KEY = NULL;
    handler->INES_TEMPLATE_ID = NULL;
    handler->INES_ORG_ID = NULL;
    handler->AWS_IOT_ENDPOINT = NULL;
    handler->AZURE_DPS_GLOBAL_DEVICE_ENDPOINT = NULL;
    handler->AZURE_DPS_ID_SCOPE = NULL;
    handler->DEVICE_NAME_PREFIX = NULL;
    handler->DEVICE_SERIAL_NUMBER = NULL;
    handler->DEVICE_COUNTRY = NULL;
    handler->FACTORY_KEY = NULL;
    handler->FACTORY_CERT=NULL;
    handler->FACTORY_KEY_PATH=NULL;
    handler->FACTORY_CERT_PATH=NULL;
    handler->INES_EST_SERVER_URL=NULL;
    handler->INES_REST_SERVER_URL=NULL;
    handler->CLIENT_CERT=NULL;
    handler->CLIENT_KEY=NULL;
    handler->CLIENT_CERT_PATH=NULL;
    handler->CLIENT_KEY_PATH=NULL;
    handler->DEVICE_CERT_PATH=NULL;
    handler->SECURE_KEY_PATH=NULL;
    handler->AWS_MQTT_ENDPOINT_URI=NULL;
    handler->PROTOCOL=NULL;
    handler->USE_VAULTIC="FALSE";
    return 0;
}

int checkConfigValue(char* configValue)
{
    if(configValue)
    {
        if (strlen(configValue)<1)
            {
                return -1;
            }
    }
    else
        return -1;

    return 0;

}

int verifyConfigStruc(int configtype, config_values_t *handler)
{
    int ret = 0;

    if(configtype==CONFIG_FILE_REST_API)
    {

        if(handler->USE_VAULTIC&&(strcmp(handler->USE_VAULTIC,"TRUE")==0))
            printf("Ines Config : Use Cert in VAULTIC for CLIENT_CERT_PATH and CLIENT_KEY_PATH\r\n");
        else
        {
            if (checkConfigValue(handler->CLIENT_CERT_PATH)<0)
            {
                handler->CLIENT_CERT_PATH=NULL;
                printf("Ines Config : missing value for CLIENT_CERT_PATH\r\n");
                ret = -1;
            }

            if (checkConfigValue(handler->CLIENT_KEY_PATH)<0)
            {
                handler->CLIENT_KEY_PATH=NULL;
                printf("Ines Config : missing value for CLIENT_KEY_PATH\r\n");
                ret = -1;
            }
        }

        if (checkConfigValue(handler->INES_REST_SERVER_URL)<0)
        {
            handler->INES_REST_SERVER_URL=NULL;
            printf("Ines Config : missing value for INES_REST_SERVER_URL\r\n");
            ret = -1;
        }

        if (checkConfigValue(handler->INES_ORG_ID)<0)
        {
            handler->INES_ORG_ID=NULL;
            printf("Ines Config : missing value for INES_ORG_ID\r\n");
            ret = -1;
        }
    }

    if(configtype==CONFIG_FILE_EST_API)
    {
        if(handler->USE_VAULTIC&&(strcmp(handler->USE_VAULTIC,"TRUE")==0))
            printf("Ines Config : Use Cert in VAULTIC for FACTORY_CERT_PATH and FACTORY_KEY_PATH\r\n");
        else
        {
            if (checkConfigValue(handler->FACTORY_CERT_PATH)<0)
            {
                handler->FACTORY_CERT_PATH=NULL;
                printf("Ines Config : missing value for FACTORY_CERT_PATH\r\n");
                ret = -1;
            }

            if (checkConfigValue(handler->FACTORY_KEY_PATH)<0)
            {
                handler->FACTORY_KEY_PATH=NULL;
                printf("Ines Config : missing value for FACTORY_KEY_PATH\r\n");
                ret = -1;
            }
        }

        if (checkConfigValue(handler->INES_EST_SERVER_URL)<0)
        {
            handler->INES_EST_SERVER_URL=NULL;
            printf("Ines Config : missing value for INES_EST_SERVER_URL\r\n");
            ret = -1;
        }
    }

    if(configtype==CONFIG_FILE_ZTP_EST||configtype==CONFIG_FILE_ZTP_REST)
    {
        if(handler->USE_VAULTIC&&(strcmp(handler->USE_VAULTIC,"TRUE")==0))
            printf("Ines Config : Use Cert in VAULTIC for SECURE_KEY_PATH\r\n");
        else
        {
            if (checkConfigValue(handler->SECURE_KEY_PATH)<0)
            {
                handler->SECURE_KEY_PATH=NULL;
                printf("Ines Config : missing value for SECURE_KEY_PATH\r\n");
                ret = -1;
            }
        }

        if (checkConfigValue(handler->DEVICE_CERT_PATH)<0)
        {
            handler->DEVICE_CERT_PATH=NULL;
            printf("Ines Config : missing value for DEVICE_CERT_PATH\r\n");
            ret = -1;
        }

        if (checkConfigValue(handler->DEVICE_NAME_PREFIX)<0)
        {
            handler->DEVICE_NAME_PREFIX=NULL;
            printf("Ines Config : missing value for DEVICE_NAME_PREFIX\r\n");
            ret = -1;
        }

        if (checkConfigValue(handler->DEVICE_SERIAL_NUMBER)<0)
        {
            handler->DEVICE_SERIAL_NUMBER=NULL;
            printf("Ines Config : missing value for DEVICE_SERIAL_NUMBER\r\n");
            ret = -1;
        }
        
        if (checkConfigValue(handler->DEVICE_COUNTRY)<0)
        {
            handler->DEVICE_COUNTRY=NULL;
            printf("Ines Config : missing value for DEVICE_COUNTRY\r\n");
            ret = -1;
        }
    }

    if(configtype==CONFIG_FILE_ZTP_REST)
    {
        if (checkConfigValue(handler->INES_TEMPLATE_ID)<0)
        {
            handler->INES_TEMPLATE_ID=NULL;
            printf("Ines Config : missing value for INES_TEMPLATE_ID\r\n");
            ret = -1;
        }
    }

    if(configtype==CONFIG_FILE_CLOUD)
    {
        if (!handler->AWS_IOT_ENDPOINT && !handler->AZURE_DPS_GLOBAL_DEVICE_ENDPOINT)
        {
            printf("ZTP Config : missing value for AWS_IOT_ENDPOINT or AZURE_DPS_GLOBAL_DEVICE_ENDPOINT\r\n");
            ret = -1;
        }

        if (handler->AWS_IOT_ENDPOINT && handler->AZURE_DPS_GLOBAL_DEVICE_ENDPOINT)
        {
            printf("ZTP Config : Can't have both value AWS_IOT_ENDPOINT or AZURE_DPS_GLOBAL_DEVICE_ENDPOINT\r\n");
            ret = -1;
        }

        if (handler->AZURE_DPS_GLOBAL_DEVICE_ENDPOINT && !handler->AZURE_DPS_ID_SCOPE)
        {
            printf("ZTP Config : missing value for AZURE_DPS_ID_SCOPE\r\n");
            ret = -1;
        }
    }

    return ret;
}

int freeConfigStruct(config_values_t*handler){

    if(handler->SECURE_CERT_PATH)
        free(handler->SECURE_CERT_PATH);
    if(handler->DEVICE_CERT)
        free(handler->DEVICE_CERT); 
    if(handler->SECURE_KEY)
        free(handler->SECURE_KEY); 
    if(handler->INES_TEMPLATE_ID)
        free(handler->INES_TEMPLATE_ID); 
    if(handler->INES_ORG_ID)
        free(handler->INES_ORG_ID); 
    if(handler->AWS_IOT_ENDPOINT)
        free(handler->AWS_IOT_ENDPOINT); 
    if(handler->AZURE_DPS_GLOBAL_DEVICE_ENDPOINT)
        free(handler->AZURE_DPS_GLOBAL_DEVICE_ENDPOINT); 
    if(handler->AZURE_DPS_ID_SCOPE)
        free(handler->AZURE_DPS_ID_SCOPE); 
    if(handler->DEVICE_CERT_PATH)
        free(handler->DEVICE_CERT_PATH);
    if(handler->SECURE_KEY_PATH)
        free(handler->SECURE_KEY_PATH);
    if(handler->AWS_MQTT_ENDPOINT_URI)
        free(handler->AWS_MQTT_ENDPOINT_URI);
    if(handler->PROTOCOL)
        free(handler->PROTOCOL);
    if(handler->DEVICE_NAME_PREFIX)
        free(handler->DEVICE_NAME_PREFIX);
    if(handler->DEVICE_COUNTRY)
        free(handler->DEVICE_COUNTRY);
    if(handler->DEVICE_SERIAL_NUMBER)
        free(handler->DEVICE_SERIAL_NUMBER);
    if(handler->FACTORY_CERT)
        free(handler->FACTORY_CERT);
    if(handler->FACTORY_KEY)
        free(handler->FACTORY_KEY);
    if(handler->FACTORY_CERT_PATH)
        free(handler->FACTORY_CERT_PATH);
    if(handler->FACTORY_KEY_PATH)
        free(handler->FACTORY_KEY_PATH);
    if(handler->INES_EST_SERVER_URL)
        free(handler->INES_EST_SERVER_URL);
    if(handler->INES_REST_SERVER_URL)
        free(handler->INES_REST_SERVER_URL);
    if(handler->CLIENT_CERT)
        free(handler->CLIENT_CERT);
    if(handler->CLIENT_KEY)
        free(handler->CLIENT_KEY);
    if(handler->CLIENT_CERT_PATH)
        free(handler->CLIENT_CERT_PATH);
    if(handler->CLIENT_KEY_PATH)
        free(handler->CLIENT_KEY_PATH);
    return 0;
}
