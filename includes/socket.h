#ifndef _SECURITY_TRM_SOCKET_H
#define _SECURITY_TRM_SOCKET_H

extern int trm_socket_post_create(struct socket *sock, int family, int type, int protocol, int kern);
extern int trm_socket_socketpair(struct socket *socka, struct socket *sockb);
extern int trm_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);
#endif