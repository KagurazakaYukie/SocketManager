#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "MArrayList.h"
#include "MArrayListTab.h"
#include "MultitThreadMemoryManager.h"
#include "ThreadManager.h"
#include <sys/epoll.h>
#include <semaphore.h>

#define WANTNONE 0;
#define WANTREAD 1;
#define WANTWRITE 2;

#define READNONE 0;
#define READTOWRITE 1;
#define READTOREAD 2;

#define SocketManagerCMP(a, b) ({\
    if(strstr(a,b)!=NULL){\
        1;\
    }\
    0;\
})

#define CloseSSL(i, ssl) ({\
    i = SSL_get_fd(ssl);\
    SSL_shutdown(ssl);\
    SSL_free(ssl);\
    close(i);\
})

#define SocketManagerAnalysisThreadLock(smatp) ({ \
    *((int *) smp->ConnectIsSuccess->m)&&(pthread_mutex_lock(smatp->mutex)==0);\
})

#define SocketManagerAnalysisThreadUnLock(smatp) ({\
     *((int *) smp->ConnectIsSuccess->m)&&(pthread_mutex_unlock(smatp->mutex)==0);\
})

typedef struct es {
    MemoryInfo *m, *e1m, *e2m, *e2mm;
    int epollfd, epollwaitfd, length;
    struct epoll_event *event1, **event2;
} SocketManagerEpollParameter;

typedef struct smatp {
    SocketManagerEpollParameter *smep;
    pthread_mutex_t *mutex;
    MemoryBigUnit *mbu;
    MemoryInfo *End;
    MArrayListTab *User;
} SocketManagerAnalysisThreadParameter;

typedef struct smsdc {
    SocketManagerAnalysisThreadParameter *smatp;
    MemoryBigUnit *tmp;
    MTMemoryManager *mm;
    MemoryInfo *WriteData, *m, *keeptime, *Port, *WriteFun, *Readto, *WritetoRead, *WANT;
    SSL *ssl;
} SocketManagerAnalysisThreadPack;

typedef struct smp {
    MemoryInfo *m, *name, *maddr;
    ThreadQueue *tq;
    MArrayList *NameParameter, **Function, *ThreadPack;
    MemoryInfo *PrivateKeyFile, *CertificateFile, *VerifyFile, *End, *ConnectIsSuccess, *IsServer;
    SocketManagerEpollParameter *smep;
    SocketManagerAnalysisThreadPack *Connect;
    struct sockaddr_in *addr;
    int LocalSocket, UserSocket;
    void *CertificateFun;
    SSL_CTX *ctx;
} SocketManagerParameter;

typedef struct sm {
    MemoryInfo *m;
    MArrayList *SocketManagerParameter;
    MemoryBigUnit *mbu;
} SocketManager;

void UserAnalysisThread(void *m);

void ServerMainThread(void *m);

void ClientConnect(void *m);

void KeepThread(void *m);

int SocketManagerSSLWrite(SocketManagerAnalysisThreadParameter *smp, SocketManagerAnalysisThreadPack *smatpack, int funi, MemoryInfo *data, int wtr);

SocketManager *SocketManagerInit(MTMemoryManager *mm);

SocketManagerParameter *SocketParameterInit(MTMemoryManager *mm, SocketManager *sm, SocketManagerEpollParameter *smep, MemoryInfo *PrivateKeyFile, MemoryInfo *CertificateFile, MemoryInfo *VerifyFile, void *CertificateFun, MArrayList *NameParameter, MArrayList **Function, MemoryInfo *addrtext, int port, bool server);

SocketManagerEpollParameter *SocketManagerEpollParameterInit(MTMemoryManager *mm, MemoryBigUnit *mbu, int i);

int SocketManagerAddSocketParameter(MTMemoryManager *mm, SocketManager *sm, MemoryInfo *name, ThreadManager *tm, SocketManagerParameter *smp, int i);

void SocketManagerAddSocketThread(MTMemoryManager *mm, SocketManager *sm, ThreadManager *tm, SocketManagerParameter *smp, int i);

void SocketManagerALLThreadSetStop(SocketManagerParameter *smp);

void SocketManagerSocketParameterDestroy(MTMemoryManager *mm, SocketManager *sm, SocketManagerParameter *smp);

void SocketManagerEpollParameterDestroy(SocketManager *sm, SocketManagerEpollParameter *smep);

void SocketManagerDestroy(SocketManager *sm);

void SocketManagerALLDestroy(MTMemoryManager *mm, SocketManager *sm);