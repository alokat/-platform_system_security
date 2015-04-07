/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <keystore/IKeystoreService.h>
#include <keystore/keystore.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

using namespace android;

static const char* responses[] = {
    NULL,
    /* [NO_ERROR]           = */ "No error",
    /* [LOCKED]             = */ "Locked",
    /* [UNINITIALIZED]      = */ "Uninitialized",
    /* [SYSTEM_ERROR]       = */ "System error",
    /* [PROTOCOL_ERROR]     = */ "Protocol error",
    /* [PERMISSION_DENIED]  = */ "Permission denied",
    /* [KEY_NOT_FOUND]      = */ "Key not found",
    /* [VALUE_CORRUPTED]    = */ "Value corrupted",
    /* [UNDEFINED_ACTION]   = */ "Undefined action",
    /* [WRONG_PASSWORD]     = */ "Wrong password (last chance)",
    /* [WRONG_PASSWORD + 1] = */ "Wrong password (2 tries left)",
    /* [WRONG_PASSWORD + 2] = */ "Wrong password (3 tries left)",
    /* [WRONG_PASSWORD + 3] = */ "Wrong password (4 tries left)",
};

static void
usage(const char *msg) {
    
    extern char *__progname;
    if (msg)
        fprintf(stderr, "%s", msg);
    
    fprintf(stderr, "usage"
                    "\t%1$s test"
                    "\t%1$s get <key>"
                    "\t%1$s insert <key> <value>"
                    "\t%1$s del"
                    "\t%1$s exist"
                    "\t%1$s saw"
                    "\t%1$s reset"
                    "\t%1$s password"
                    "\t%1$s lock"
                    "\t%1$s unlock"
                    "\t%1$s zero",
        __progname);
        exit(1);
}

static int
saw(sp<IKeystoreService> service, const String16& name, int uid) {
    Vector<String16> matches;
    int32_t ret = service->saw(name, uid, &matches);
    if (ret < 0) {
        usage("could not connect to keystor service");
        /* NOTREACHED */
    } else if (ret != ::NO_ERROR) {
        fprintf(stderr, "saw: %s (%d)\n", responses[ret], ret);
        return 1;
    } else {
        Vector<String16>::const_iterator it = matches.begin();
        for (; it != matches.end(); ++it) {
            printf("%s\n", String8(*it).string());
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s action [parameter ...]\n", argv[0]);
        return 1;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);

    if (service == NULL) {
        fprintf(stderr, "%s: error: could not connect to keystore service\n", argv[0]);
        return 1;
    }

    /*
     * All the commands should return a value
     */

    if (strcmp(argv[1], "test") == 0) {
        int32_t ret = service->test();
        if (ret < 0) {
            usage("could not connect to keystore service");
            /* NOTREACHED */
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    if (strcmp(argv[1], "get") == 0) {
        if (argc < 3) {
            usage(NULL);
            /* NOTREACHED */
        }
        uint8_t* data;
        size_t dataSize;
        int32_t ret = service->get(String16(argv[2]), &data, &dataSize);
        if (ret < 0) {
            fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret);
            return 1;
        } else if (ret != ::NO_ERROR) {
            fprintf(stderr, "%s: : %s (%d)\n", argv[0], responses[ret], ret);
            return 1;
        } else {
            fwrite(data, dataSize, 1, stdout);
            fflush(stdout);
            free(data);
            return 0;
        }
    }
                
    if (strcmp(argv[1], "del") == 0) {
        if (argc < 3) {
            usage(NULL);
            /* NOTREACHED */
        }
        int uid = -1;
        if (argc > 3) {
            uid = atoi(argv[3]);
            fprintf(stderr, "Running as uid %d\n", uid);
        }
        int32_t ret = service->del(String16(argv[2]), uid);
        if (ret < 0) {
            fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret);
            return 1;
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    if (strcmp(argv[1], "exit") == 0) {
        if (argc < 3) {
            usage(NULL);
            /* NOTREACHED */
        }
        int uid = -1;
        if (argc > 3) {
            uid = atoi(argv[3]);
            fprintf(stderr, "Running as uid %d\n", uid);
        }
        int32_t ret = service->exist(String16(argv[2]), uid);
        if (ret < 0) {
            fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret);
            return 1;
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    if (strcmp(argv[1], "saw") == 0) {
        return saw(service, argc < 3 ? String16("") : String16(argv[2]),
                argc < 4 ? -1 : atoi(argv[3]));
    }

    if (strcmp(argv[1], "reset") == 0) {
        int32_t ret = service->reset();
        if (ret < 0) {
            usage("could not connect to keystore service");
            /* NOTREACHED */
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    if (strcmp(argv[1], "password") == 0) {
        if (argc < 3) {
            usage(NULL);
            /* NOTREACHED */
        }
        int32_t ret = service->password(String16(argv[2]));
        if (ret < 0) {
            fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret);
            return 1;
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    if (strcmp(argv[1], "lock") == 0) {
        int32_t ret = service->lock();
        if (ret < 0) {
            usage("could not connect to keystore service");
            /* NOTREACHED */
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    if (strcmp(argv[1], "unlock") == 0) {
        if (argc < 3) {
            usage(NULL);
            /* NOTREACHED */
        }
        int32_t ret = service->unlock(String16(argv[2]));
        if (ret < 0) {
            fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret);
            return 1;
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    if (strcmp(argv[1], "zero") == 0) {
        int32_t ret = service->zero();
        if (ret < 0) {
            usage("could not connect to keystore service");
            /* NOTREACHED */
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    if (strcmp(argv[1], "get_pubkey") == 0) {
        if (argc < 3) {
            usage(NULL);
            /* NOTREACHED */
        }
        uint8_t* data;
        size_t dataSize;
        int32_t ret = service->get_pubkey(String16(argv[2]), &data, &dataSize);
        if (ret < 0) {
            fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret);
            return 1;
        } else if (ret != ::NO_ERROR) {
            fprintf(stderr, "%s: : %s (%d)\n", argv[0], responses[ret], ret);
            return 1;
        } else {
            fwrite(data, dataSize, 1, stdout);
            fflush(stdout);
            free(data);
            return 0;
        }
    }
    if (strcmp(argv[1], "del_key") == 0) {
        if (argc < 3) {
            usage(NULL);
            /* NOTREACHED */
        }
        int uid = -1;
        if (argc > 3) {
            uid = atoi(argv[3]);
            fprintf(stderr, "Running as uid %d\n", uid);
        }
        int32_t ret = service->del_key(String16(argv[2]), uid);
        if (ret < 0) {
            fprintf(stderr, "%s: could not connect: %d\n", argv[0], ret);
            return 1;
        } else {
            printf(": %s (%d)\n", responses[ret], ret);
            return 0;
        }
    }

    fprintf(stderr, "%s: unknown command: %s\n", argv[0], argv[1]);
    return 1;
}
