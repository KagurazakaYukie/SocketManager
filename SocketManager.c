#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "MArrayList.h"
#include "MultitThreadMemoryManager.h"
#include "ThreadManager.h"
#include <sys/epoll.h>
#include "SocketManager.h"
#include <fcntl.h>
#include "Init.h"
#include <netinet/tcp.h>

void UserAnalysisThread(void *m) {
    ThreadInfo *ti = (ThreadInfo *) m;
    MTMemoryManager *mm = (MTMemoryManager *) ti->tpa->tpm->mm;
    SocketManagerParameter *smp = (SocketManagerParameter *) ti->data;
    SocketManagerAnalysisThreadParameter *smatp = (SocketManagerAnalysisThreadParameter *) MTMemoryManagerUnitCalloc(mm, ti->tpa->mbu, sizeof(SocketManagerAnalysisThreadParameter))->m;
    SocketManagerEpollParameter *smep = SocketManagerEpollParameterInit(mm, ti->tpa->mbu, smp->smep->length);
    pthread_mutex_t *mutex = (pthread_mutex_t *) MTMemoryManagerUnitCalloc(mm, ti->tpa->mbu, sizeof(pthread_mutex_t))->m;
    pthread_mutexattr_t *mutexattr = (pthread_mutexattr_t *) MTMemoryManagerUnitCalloc(mm, ti->tpa->mbu, sizeof(pthread_mutexattr_t))->m;
    pthread_mutexattr_setprotocol(mutexattr, PTHREAD_PRIO_INHERIT);
    pthread_mutexattr_settype(mutexattr, PTHREAD_MUTEX_ADAPTIVE_NP);
    pthread_mutex_init(mutex, mutexattr);
    smatp->smep = smep;
    smatp->mbu = ti->tpa->mbu;
    smatp->User = MBUArrayListTabInit(mm, ti->tpa->mbu);
    smatp->End = MTMemoryManagerUnitCalloc(mm, ti->tpa->mbu, sizeof(int));
    *((int *) smatp->End->m) = 1;
    smatp->mutex = mutex;
    ti->tpa->ReturnData = smatp;
    MemoryInfo *tmp = MTMemoryManagerUnitCalloc(mm, ti->tpa->mbu, AllocateMemory);
    MArrayList *INFunction = smp->Function[0], *OUTFunction = smp->Function[1], *HUPFunction = smp->Function[2];
    SocketManagerAnalysisThreadPack *smatpack;
    int epollt, itmp, len, err;
    while (1) {
        if (pthread_mutex_lock(mutex) == 0 && (*((int *) smatp->End->m))) {
            epollt = (smep->epollwaitfd = epoll_wait(smep->epollfd, *(smep->event2), smep->length, 12));
            if (epollt > 0) {
                for (int j = 0; j < epollt; ++j) {
                    if (smep->event2[j]->data.fd != smp->LocalSocket) {
                        if (smep->event2[j]->events & EPOLLIN) {
                            smatpack = (SocketManagerAnalysisThreadPack *) smep->event2[j]->data.ptr;
                            if (SSL_get_fd(smatpack->ssl) != -1) {
                                if ((len = SSL_read(smatpack->ssl, tmp->m, AllocateMemory)) > 0) {
                                    for (int i = 0; i < MArrayListSize(smp->NameParameter); ++i) {
                                        if (strstr(tmp->m, (char *) ((MemoryInfo *) MArrayListGetIndex(smp->NameParameter, i))->m) != NULL) {
                                            smatpack->tmp = ti->tpa->mbu;
                                            *((time_t *) smatpack->keeptime->m) = time(NULL);
                                            (*((Ft) (MArrayListGetIndex(INFunction, i))))(smatpack);
                                            *((int *) smatpack->WANT->m) = WANTNONE;
                                            if (*((int *) smatpack->Readto->m) == 1) {
                                                smep->event1->events = EPOLLOUT | EPOLLONESHOT | EPOLLET;
                                                epoll_ctl(smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smep->event1);
                                            }
                                            if (*((int *) smatpack->Readto->m) == 2) {
                                                smep->event1->events = EPOLLIN | EPOLLONESHOT | EPOLLET;
                                                epoll_ctl(smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smep->event1);
                                            }
                                        }
                                    }
                                } else {
                                    err = SSL_get_error(smatpack->ssl, len);
                                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                                        *((int *) smatpack->WANT->m) = WANTREAD;
                                        smep->event1->events |= EPOLLIN | EPOLLONESHOT | EPOLLET;
                                        epoll_ctl(smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smep->event1);
                                    } else {
                                        smep->event1->events = EPOLLRDHUP | EPOLLONESHOT | EPOLLET;
                                        epoll_ctl(smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smep->event1);
                                    }
                                }
                            }
                        }
                        if (smep->event2[j]->events & EPOLLOUT) {
                            smatpack = (SocketManagerAnalysisThreadPack *) smep->event2[j]->data.ptr;
                            if (SSL_get_fd(smatpack->ssl) != -1) {
                                *((time_t *) smatpack->keeptime->m) = time(NULL);
                                if (*((unsigned long *) smatpack->WriteFun->m) != -1) {
                                    (*((Ft) (MArrayListGetIndex(OUTFunction, *((unsigned long *) smatpack->WriteFun->m)))))(smatpack);
                                }
                                len = SSL_write(smatpack->ssl, smatpack->WriteData->m, strlen(smatpack->WriteData->m));
                                if (len < 0) {
                                    err = SSL_get_error(smatpack->ssl, len);
                                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                                        *((int *) smatpack->WANT->m) = WANTWRITE;
                                        smep->event1->events |= EPOLLOUT | EPOLLONESHOT | EPOLLET;
                                        epoll_ctl(smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smep->event1);
                                    } else {
                                        smep->event1->events = EPOLLRDHUP | EPOLLONESHOT | EPOLLET;
                                        epoll_ctl(smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smep->event1);
                                    }
                                }
                                *((int *) smatpack->WANT->m) = WANTNONE;
                                if (*((int *) smatpack->WritetoRead->m)) {
                                    smep->event1->events = EPOLLIN | EPOLLONESHOT | EPOLLET;
                                    epoll_ctl(smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smep->event1);
                                }
                            }
                        }
                        if (smep->event2[j]->events & EPOLLRDHUP) {
                            smatpack = ((SocketManagerAnalysisThreadPack *) smep->event2[j]->data.ptr);
                            (*((Ft) (MArrayListGetIndex(HUPFunction, 0))))(smatpack);
                            epoll_ctl(smep->epollfd, EPOLL_CTL_DEL, SSL_get_fd(smatpack->ssl), smep->event1);
                            MTMemoryManagerUnitFree(ti->tpa->mbu, smatpack->WriteData);
                            MTMemoryManagerUnitFree(ti->tpa->mbu, smatpack->keeptime);
                            MTMemoryManagerUnitFree(ti->tpa->mbu, smatpack->Port);
                            MTMemoryManagerUnitFree(ti->tpa->mbu, smatpack->WriteFun);
                            MTMemoryManagerUnitFree(ti->tpa->mbu, smatpack->Readto);
                            MTMemoryManagerUnitFree(ti->tpa->mbu, smatpack->WritetoRead);
                            MTMemoryManagerUnitFree(ti->tpa->mbu, smatpack->WANT);
                            MTMemoryManagerUnitFree(ti->tpa->mbu, smatpack->m);
                            CloseSSL(itmp, smatpack->ssl);

                        }
                    }
                }
            }
            if (!*((int *) smp->IsServer->m)) {
                for (int i = 0; i < MArrayListTabSize(smatp->User); ++i) {
                    if ((smatpack = MArrayListTabGetIndex(smatp->User, i)) != NULL && difftime(time(NULL), *((time_t *) smatpack->keeptime->m)) >= 6) {
                        strcpy(smatpack->WriteData->m, "keep");
                        *((unsigned long *) smatpack->WriteFun->m) = -1;
                        *((int *) smatpack->WritetoRead->m) = 0;
                        smatp->smep->event1->events |= EPOLLOUT | EPOLLONESHOT | EPOLLET;
                        epoll_ctl(smatp->smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smatp->smep->event1);
                    }
                }
            }
            pthread_mutex_unlock(mutex);
        } else {
            goto end;
        }
    }

    end:
    pthread_mutex_unlock(mutex);
    pthread_mutex_destroy(mutex);
    MTMemoryManagerAppointComleteInitUnit(ti->tpa->mbu);
}

void ServerMainThread(void *m) {
    ThreadInfo *ti = (ThreadInfo *) m;
    MTMemoryManager *mm = ti->tpa->tpm->mm;
    SocketManagerParameter *smp = (SocketManagerParameter *) ti->data;

    struct sockaddr_in *addr = (struct sockaddr_in *) MTMemoryManagerUnitCalloc(mm, ti->tpa->mbu, sizeof(struct sockaddr_in))->m;
    unsigned int len = sizeof(addr);

    MemoryInfo *smatmpackm;
    SocketManagerAnalysisThreadPack *smatpack;
    SocketManagerAnalysisThreadParameter *smatp;
    int epollt, i = 0, listsize, err;
    SSL *ssl;
    while (*((int *) smp->End->m)) {
        epollt = (smp->smep->epollwaitfd = epoll_wait(smp->smep->epollfd, *(smp->smep->event2), smp->smep->length, 12));
        if (epollt > 0) {
            listsize = epollt >= MArrayListSize(smp->ThreadPack) ? MArrayListSize(smp->ThreadPack) - 1 : epollt;
            for (int i = 0; i < listsize; i++) {
                if ((smatp = (SocketManagerAnalysisThreadParameter *) ((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, i))->ReturnData) != NULL) {
                    pthread_mutex_lock(smatp->mutex);
                }
            }
            for (int j = 0; j < epollt; ++j) {
                if (smp->smep->event2[j]->data.fd == smp->LocalSocket) {
                    if ((smatp = (SocketManagerAnalysisThreadParameter *) ((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, i))->ReturnData) != NULL) {
                        if ((smp->UserSocket = accept(smp->LocalSocket, (struct sockaddr *) addr, &len)) != -1) {
                            printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(addr->sin_addr), htons(addr->sin_port), smp->UserSocket);
                        }
                        ssl = SSL_new(smp->ctx);
                        SSL_set_fd(ssl, smp->UserSocket);
                        appept:
                        if ((err = SSL_accept(ssl)) != 1) {
                            if (SSL_get_error(smatpack->ssl, err) == SSL_ERROR_WANT_ACCEPT) {
                                goto appept;
                            }
                            close(smp->UserSocket);
                            continue;
                        }
                        if ((*((Ft) (smp->CertificateFun)))(ssl)) {
                            smatmpackm = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(SocketManagerAnalysisThreadPack));
                            smatpack = (SocketManagerAnalysisThreadPack *) smatmpackm->m;
                            smatpack->m = smatmpackm;
                            smatpack->ssl = ssl;
                            smatpack->smatp = smatp;
                            smatpack->Port = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(int));
                            smatpack->Readto = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(int));
                            smatpack->WritetoRead = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(int));
                            smatpack->WANT = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(int));
                            smatpack->WriteFun = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(unsigned long));
                            *((unsigned long *) smatpack->WriteFun->m) = -1;
                            *((int *) smatpack->Port->m) = htons(addr->sin_port);
                            smatpack->mm = mm;
                            smatpack->WriteData = MTMemoryManagerUnitCalloc(mm, smatp->mbu, AllocateMemory);
                            smatpack->keeptime = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(time_t));
                            *((time_t *) smatpack->keeptime->m) = time(NULL);
                            MBUarrayListTabAddIndex(mm, smatp->mbu, smatp->User, smatpack);
                            smatp->smep->event1->data.ptr = smatpack;
                            smatp->smep->event1->events = EPOLLIN | EPOLLONESHOT | EPOLLET;
                            epoll_ctl(smatp->smep->epollfd, EPOLL_CTL_ADD, SSL_get_fd(ssl), smatp->smep->event1);
                            i++;
                            i = listsize == i ? 0 : i;
                        } else {
                            smatp->smep->event1->events = EPOLLRDHUP | EPOLLONESHOT | EPOLLET;
                            epoll_ctl(smatp->smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smatp->smep->event1);
                        }
                    }
                }
            }
            for (int i = 0; i < listsize; i++) {
                if ((smatp = (SocketManagerAnalysisThreadParameter *) ((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, i))->ReturnData) != NULL) {
                    pthread_mutex_unlock(smatp->mutex);
                }
            }
        }
    }
    MTMemoryManagerAppointComleteInitUnit(ti->tpa->mbu);
}

void ClientConnect(void *m) {
    ThreadInfo *ti = (ThreadInfo *) m;
    MTMemoryManager *mm = ti->tpa->tpm->mm;
    SocketManagerParameter *smp = (SocketManagerParameter *) ti->data;
    MemoryInfo *smatmpackm;
    SocketManagerAnalysisThreadPack *smatpack;
    SocketManagerAnalysisThreadParameter *smatp;
    SSL *ssl;
    int err;
    for (;;) {
        for (int i = 0; i < MArrayListSize(smp->ThreadPack); ++i) {
            if ((smatp = (SocketManagerAnalysisThreadParameter *) ((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, i))->ReturnData) != NULL) {
                pthread_mutex_lock(smatp->mutex);
                ssl = SSL_new(smp->ctx);
                SSL_set_fd(ssl, smp->LocalSocket);
                connect:
                if ((err = SSL_connect(ssl)) != 1) {
                    if (SSL_get_error(smatpack->ssl, err) == SSL_ERROR_WANT_CONNECT) {
                        goto connect;
                    }
                    close(smp->LocalSocket);
                    *((int *) smp->ConnectIsSuccess->m) = -199;
                    goto end;
                }
                fcntl(smp->LocalSocket, F_SETFL, fcntl(smp->LocalSocket, F_GETFL, 0) | O_NONBLOCK);
                if ((*((Ft) (smp->CertificateFun)))(ssl)) {
                    smatmpackm = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(SocketManagerAnalysisThreadPack));
                    smatpack = (SocketManagerAnalysisThreadPack *) smatmpackm->m;
                    smatpack->m = smatmpackm;
                    smatpack->ssl = ssl;
                    smatpack->smatp = smatp;
                    smatpack->Readto = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(int));
                    smatpack->WritetoRead = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(int));
                    smatpack->Port = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(int));
                    smatpack->WANT = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(int));
                    smatpack->WriteFun = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(unsigned long));
                    *((unsigned long *) smatpack->WriteFun->m) = -1;
                    smatpack->mm = mm;
                    smatpack->WriteData = MTMemoryManagerUnitCalloc(mm, smatp->mbu, AllocateMemory);
                    smatpack->keeptime = MTMemoryManagerUnitCalloc(mm, smatp->mbu, sizeof(time_t));
                    *((time_t *) smatpack->keeptime->m) = time(NULL);
                    MBUarrayListTabAddIndex(mm, smatp->mbu, smatp->User, smatpack);
                    smatp->smep->event1->data.ptr = smatpack;
                    smatp->smep->event1->events = EPOLLONESHOT | EPOLLET;
                    epoll_ctl(smatp->smep->epollfd, EPOLL_CTL_ADD, SSL_get_fd(ssl), smatp->smep->event1);
                    smp->Connect = smatpack;
                    *((int *) smp->ConnectIsSuccess->m) = 1;
                } else {
                    smatp->smep->event1->events = EPOLLRDHUP | EPOLLONESHOT | EPOLLET;
                    epoll_ctl(smatp->smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smatp->smep->event1);
                    *((int *) smp->ConnectIsSuccess->m) = -999;
                }
                pthread_mutex_unlock(smatp->mutex);
                goto end;
            }
        }
    }

    end:
    MTMemoryManagerAppointComleteInitUnit(ti->tpa->mbu);
}

void KeepThread(void *m) {
    ThreadInfo *ti = (ThreadInfo *) m;
    MTMemoryManager *mm = ti->tpa->tpm->mm;
    SocketManagerParameter *smp = (SocketManagerParameter *) ti->data;
    SocketManagerAnalysisThreadPack *smatpack;
    SocketManagerAnalysisThreadParameter *smatp;
    MArrayList *keepi = MBUArrayListInit(mm, ti->tpa->mbu);
    MemoryInfo *tmpi;
    while (*((int *) smp->End->m)) {
        for (int i = 0; i < MArrayListSize(smp->ThreadPack); ++i) {
            if ((smatp = (SocketManagerAnalysisThreadParameter *) ((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, i))->ReturnData) != NULL) {
                for (int j = 0; j < MArrayListTabSize(smatp->User); ++j) {
                    if ((smatpack = MArrayListTabGetIndex(smatp->User, j)) != NULL && difftime(time(NULL), *((time_t *) smatpack->keeptime->m)) >= 30) {
                        tmpi = MTMemoryManagerUnitCalloc(mm, ti->tpa->mbu, sizeof(unsigned long));
                        *((unsigned long *) tmpi->m) = j;
                        MBUArrayListAddIndex(mm, ti->tpa->mbu, keepi, tmpi);
                    }
                }

                pthread_mutex_lock(smatp->mutex);
                for (int j = 0; j < MArrayListSize(keepi); ++j) {
                    tmpi = MArrayListGetIndex(keepi, j);
                    smatp->smep->event1->events = EPOLLOUT | EPOLLONESHOT | EPOLLET;
                    epoll_ctl(smatp->smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(((SocketManagerAnalysisThreadPack *) MArrayListTabGetIndex(smatp->User, *((unsigned long *) tmpi->m)))->ssl), smatp->smep->event1);
                    MArrayListTabMark(mm, smatp->User, *((unsigned long *) tmpi->m));
                    MTMemoryManagerUnitFree(ti->tpa->mbu, tmpi);
                }
                keepi->length = 0;
                pthread_mutex_unlock(smatp->mutex);

            }
        }
    }
    MTMemoryManagerAppointComleteInitUnit(ti->tpa->mbu);
}

int SocketManagerSSLWrite(SocketManagerAnalysisThreadParameter *smatp, SocketManagerAnalysisThreadPack *smatpack, int funi, MemoryInfo *data, int wtr) {
    if (data->size > smatpack->WriteData->size) {
        pthread_mutex_unlock(smatpack->smatp->mutex);
        return 0;
    }
    *((unsigned long *) smatpack->WriteFun->m) = funi;
    *((int *) smatpack->WritetoRead->m) = wtr;
    memcpy(smatpack->WriteData->m, data->m, data->size);
    smatp->smep->event1->events = EPOLLOUT | EPOLLONESHOT | EPOLLET;
    epoll_ctl(smatp->smep->epollfd, EPOLL_CTL_MOD, SSL_get_fd(smatpack->ssl), smatp->smep->event1);
    return 1;
}

SocketManager *SocketManagerInit(MTMemoryManager *mm) {
    MemoryBigUnit *mbu = MTMemoryManagerBindingThread(mm, 2);
    MemoryInfo *mi = MTMemoryManagerUnitCalloc(mm, mbu, sizeof(SocketManager));
    SocketManager *sm = (SocketManager *) mi->m;
    sm->m = mi;
    sm->mbu = mbu;
    sm->SocketManagerParameter = MBUArrayListInit(mm, sm->mbu);
    return sm;
}

SocketManagerParameter *SocketParameterInit(MTMemoryManager *mm, SocketManager *sm, SocketManagerEpollParameter *smep, MemoryInfo *PrivateKeyFile, MemoryInfo *CertificateFile, MemoryInfo *VerifyFile, void *CertificateFun, MArrayList *NameParameter, MArrayList **Function, MemoryInfo *addrtext, int port, bool server) {
    MemoryInfo *mi = MTMemoryManagerUnitCalloc(mm, sm->mbu, sizeof(SocketManagerParameter));
    MemoryInfo *maddr = MTMemoryManagerUnitCalloc(mm, sm->mbu, sizeof(struct sockaddr_in));
    SocketManagerParameter *smp = (SocketManagerParameter *) mi->m;
    smp->PrivateKeyFile = PrivateKeyFile;
    smp->CertificateFile = CertificateFile;
    smp->VerifyFile = VerifyFile;
    smp->NameParameter = NameParameter;
    smp->Function = Function;
    smp->CertificateFun = CertificateFun;
    smp->ThreadPack = MBUArrayListInit(mm, sm->mbu);
    smp->tq = MBUThreadQueueInit(mm, sm->mbu);
    smp->ConnectIsSuccess = MTMemoryManagerUnitCalloc(mm, sm->mbu, sizeof(int));
    smp->IsServer = MTMemoryManagerUnitCalloc(mm, sm->mbu, sizeof(int));
    smp->End = MTMemoryManagerUnitCalloc(mm, sm->mbu, sizeof(int));
    *((int *) smp->IsServer->m) = server;
    *((int *) smp->ConnectIsSuccess->m) = 0;
    *((int *) smp->End->m) = 1;
    smp->smep = smep;
    smp->m = mi;
    struct sockaddr_in *addr = (struct sockaddr_in *) maddr->m;
    smp->addr = addr;
    smp->maddr = maddr;
    bzero(addr, sizeof(struct sockaddr_in));
    addr->sin_family = PF_INET;
    addr->sin_port = htons(port);
    if (server) {
        addr->sin_addr.s_addr = INADDR_ANY;
    } else {
        addr->sin_addr.s_addr = inet_addr(addrtext->m);
    }
    return smp;
}

SocketManagerEpollParameter *SocketManagerEpollParameterInit(MTMemoryManager *mm, MemoryBigUnit *mbu, int i) {
    MemoryInfo *mi = MTMemoryManagerUnitCalloc(mm, mbu, sizeof(SocketManagerEpollParameter));
    MemoryInfo *mi1 = MTMemoryManagerUnitCalloc(mm, mbu, sizeof(struct epoll_event));
    MemoryInfo *mi2 = MTMemoryManagerUnitCalloc(mm, mbu, sizeof(struct epoll_event) * i);
    MemoryInfo *mi2mm = MTMemoryManagerUnitCalloc(mm, mbu, sizeof(MemoryInfo) * i);
    SocketManagerEpollParameter *smep = (SocketManagerEpollParameter *) mi->m;
    smep->m = mi;
    smep->epollfd = epoll_create(i);
    smep->e1m = mi1;
    smep->e2m = mi2;
    smep->e2mm = mi2mm;
    smep->length = i;
    smep->event1 = (struct epoll_event *) mi1->m;
    smep->event2 = (struct epoll_event **) mi2->m;
    MemoryInfo **m2mm = (MemoryInfo **) mi2mm->m;
    MemoryInfo *tmp = NULL;
    for (int ii = 0; ii < i; ii++) {
        tmp = MTMemoryManagerUnitCalloc(mm, mbu, sizeof(struct epoll_event));
        m2mm[ii] = tmp;
        smep->event2[ii] = tmp->m;
    }
    return smep;
}

int SocketManagerAddSocketParameter(MTMemoryManager *mm, SocketManager *sm, MemoryInfo *name, ThreadManager *tm, SocketManagerParameter *smp, int i) {
    smp->name = name;
    MBUArrayListAddIndex(mm, sm->mbu, sm->SocketManagerParameter, smp);
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    if (*((int *) smp->IsServer->m)) {
        if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
            return -1;
        } else {
            smp->ctx = ctx;
        }
    } else {
        if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
            return -1;
        } else {
            smp->ctx = ctx;
        }
    }

    if (smp->VerifyFile != NULL && smp->CertificateFile != NULL && smp->PrivateKeyFile != NULL) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        if (!SSL_CTX_load_verify_locations(ctx, smp->VerifyFile->m, NULL)) {
            return -2;
        }

        if (SSL_CTX_use_certificate_file(ctx, smp->CertificateFile->m, SSL_FILETYPE_PEM) <= 0) {
            return -3;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, smp->PrivateKeyFile->m, SSL_FILETYPE_PEM) <= 0) {
            return -4;
        }

        if (!SSL_CTX_check_private_key(ctx)) {
            return -5;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    if ((smp->LocalSocket = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        return -6;
    }

    int on = 1;
    setsockopt(smp->LocalSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(smp->LocalSocket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));

    int off = 0;
    setsockopt(smp->LocalSocket, SOL_SOCKET, SO_SNDBUF, &off, sizeof(off));
    setsockopt(smp->LocalSocket, SOL_SOCKET, SO_RCVBUF, &off, sizeof(off));

    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(smp->LocalSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    tv.tv_sec = 120;
    tv.tv_usec = 0;
    setsockopt(smp->LocalSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int keepidle = 500;
    setsockopt(smp->LocalSocket, SOL_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    int interval = 60;
    setsockopt(smp->LocalSocket, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    int cnt = 10;
    setsockopt(smp->LocalSocket, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));

    ThreadPack *tp;
    if (*((int *) smp->IsServer->m)) {
        fcntl(smp->LocalSocket, F_SETFL, fcntl(smp->LocalSocket, F_GETFL, 0) | O_NONBLOCK);
        if (bind(smp->LocalSocket, (struct sockaddr *) smp->addr, sizeof(struct sockaddr)) != 0) {
            return -7;
        }

        if (listen(smp->LocalSocket, smp->smep->length) == -1) {
            return -8;
        }

        smp->smep->event1->data.fd = smp->LocalSocket;
        smp->smep->event1->events = EPOLLIN | EPOLLET;
        epoll_ctl(smp->smep->epollfd, EPOLL_CTL_ADD, smp->LocalSocket, smp->smep->event1);

        if (i < 3) {
            i = 3;
        }
        for (int j = 0; j < i - 2; ++j) {
            tp = ThreadManagerAddThread(mm, tm, smp->tq);
            MBUArrayListAddIndex(mm, sm->mbu, smp->ThreadPack, tp);
            ThreadManagerAddTask(mm, smp->tq, UserAnalysisThread, smp, NULL);
        }
        tp = ThreadManagerAddThread(mm, tm, smp->tq);
        MBUArrayListAddIndex(mm, sm->mbu, smp->ThreadPack, tp);
        ThreadManagerAddTask(mm, smp->tq, KeepThread, smp, NULL);
        tp = ThreadManagerAddThread(mm, tm, smp->tq);
        MBUArrayListAddIndex(mm, sm->mbu, smp->ThreadPack, tp);
        ThreadManagerAddTask(mm, smp->tq, ServerMainThread, smp, NULL);
        *((int *) smp->ConnectIsSuccess->m) = 1;
        return 1;
    } else {
        if (connect(smp->LocalSocket, (struct sockaddr *) smp->addr, sizeof(struct sockaddr)) < 0) {
            return -9;
        }
        tp = ThreadManagerAddThread(mm, tm, smp->tq);
        MBUArrayListAddIndex(mm, sm->mbu, smp->ThreadPack, tp);
        ThreadManagerAddTask(mm, smp->tq, UserAnalysisThread, smp, NULL);
        tp = ThreadManagerAddThread(mm, tm, smp->tq);
        MBUArrayListAddIndex(mm, sm->mbu, smp->ThreadPack, tp);
        ThreadManagerAddTask(mm, smp->tq, ClientConnect, smp, NULL);
        return 1;
    }
}

void SocketManagerAddSocketThread(MTMemoryManager *mm, SocketManager *sm, ThreadManager *tm, SocketManagerParameter *smp, int i) {
    ThreadPack *tp;
    for (int j = 0; j < i; ++j) {
        tp = ThreadManagerAddThread(mm, tm, smp->tq);
        MBUArrayListAddIndex(mm, sm->mbu, smp->ThreadPack, tp);
        ThreadManagerAddTask(mm, smp->tq, UserAnalysisThread, smp, NULL);
    }
}

void SocketManagerALLThreadSetStop(SocketManagerParameter *smp) {
    SocketManagerAnalysisThreadParameter *smatp;
    for (int j = 0; j < MArrayListSize(smp->ThreadPack); ++j) {
        if ((smatp = (SocketManagerAnalysisThreadParameter *) ((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, j))->ReturnData) != NULL) {
            *((int *) smatp->End->m) = 0;
            ThreadManagerSetThreadState(((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, j))->tid, ThreadStateWaitDestroy);
        } else {
            *((int *) smp->End->m) = 0;
            ThreadManagerSetThreadState(((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, j))->tid, ThreadStateWaitDestroy);
        }
    }
}

void SocketManagerSocketParameterDestroy(MTMemoryManager *mm, SocketManager *sm, SocketManagerParameter *smp) {
    SSL_CTX_free(smp->ctx);
    MBUArrayListDestroy(sm->mbu, smp->ThreadPack);
    MBUThreadQueueDestroy(mm, smp->tq, sm->mbu);
    MTMemoryManagerUnitFree(sm->mbu, smp->End);
    MTMemoryManagerUnitFree(sm->mbu, smp->maddr);
    MTMemoryManagerUnitFree(sm->mbu, smp->IsServer);
    MTMemoryManagerUnitFree(sm->mbu, smp->m);
}

void SocketManagerEpollParameterDestroy(SocketManager *sm, SocketManagerEpollParameter *smep) {
    MemoryInfo **m2mm = (MemoryInfo **) smep->e2mm->m;
    for (int ii = 0; ii < smep->length; ii++) {
        MTMemoryManagerUnitFree(sm->mbu, m2mm[ii]);
    }
    MTMemoryManagerUnitFree(sm->mbu, smep->e2mm);
    MTMemoryManagerUnitFree(sm->mbu, smep->e2m);
    MTMemoryManagerUnitFree(sm->mbu, smep->e1m);
    MTMemoryManagerUnitFree(sm->mbu, smep->m);
}

void SocketManagerDestroy(SocketManager *sm) {
    MTMemoryManagerAppointComleteInitUnit(sm->mbu);
}

void SocketManagerALLDestroy(MTMemoryManager *mm, SocketManager *sm) {
    SocketManagerParameter *smp;
    SocketManagerAnalysisThreadParameter *smatp;
    for (int i = 0; i < MArrayListSize(sm->SocketManagerParameter); ++i) {
        smp = MArrayListGetIndex(sm->SocketManagerParameter, i);
        for (int j = 0; j < MArrayListSize(smp->ThreadPack); ++j) {
            if ((smatp = (SocketManagerAnalysisThreadParameter *) ((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, j))->ReturnData) != NULL) {
                *((int *) smatp->End->m) = 0;
                ThreadManagerSetThreadState(((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, j))->tid, ThreadStateWaitDestroy);
            } else {
                *((int *) smp->End->m) = 0;
                ThreadManagerSetThreadState(((ThreadPack *) MArrayListGetIndex(smp->ThreadPack, j))->tid, ThreadStateWaitDestroy);
            }
        }
        MBUThreadQueueDestroy(mm, smp->tq, sm->mbu);
        SSL_CTX_free(smp->ctx);
    }
    MTMemoryManagerAppointComleteInitUnit(sm->mbu);
}