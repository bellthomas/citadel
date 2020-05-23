#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/kobject.h>
#include <linux/crypto.h>
#include <linux/mutex.h>
#include <linux/dcache.h>
#include <net/sock.h>
#include <linux/random.h>

#include "../../includes/citadel.h"
#include "../../includes/socket.h"

/*
 * Called on socket data when parent is seen to be tainted. 
 */
static void realm_init_socket(citadel_inode_data_t *inode_data) {
    if (!inode_data->in_realm) {
        inode_data->is_socket = true;
        inode_data->checked_disk_xattr = true;
        inode_data->in_realm = true;
        get_random_bytes(inode_data->identifier, _CITADEL_IDENTIFIER_LENGTH);
    }
}

static void realm_init_socket_copy(citadel_inode_data_t *original, citadel_inode_data_t *copy) {
    if (original->in_realm) {
        copy->in_realm = true;
        memcpy(copy->identifier, original->identifier, _CITADEL_IDENTIFIER_LENGTH);
    }
}
/*
 *	This hook allows a module to update or allocate a per-socket security
 *	structure. Note that the security field was not added directly to the
 *	socket structure, but rather, the socket security information is stored
 *	in the associated inode.  Typically, the inode alloc_security hook will
 *	allocate and and attach security information to
 *	SOCK_INODE(sock)->i_security.  This hook may be used to update the
 *	SOCK_INODE(sock)->i_security field with additional information that
 *	wasn't available when the inode was allocated.
 *	@sock contains the newly created socket structure.
 *	@family contains the requested protocol family.
 *	@type contains the requested communications type.
 *	@protocol contains the requested protocol.
 *	@kern set to 1 if a kernel socket.
 */
int trm_socket_post_create(struct socket *sock, int family, int type, int protocol, int kern) {
    struct inode *s_inode = SOCK_INODE(sock);
    citadel_inode_data_t *inode_data = trm_inode(s_inode);
    citadel_task_data_t *task_data = citadel_cred(current_cred());

    task_housekeeping();
    if (inode_data) {
        inode_data->is_socket = true;
        inode_data->checked_disk_xattr = true;
        if (task_data->in_realm) {
            // Automatically restrict sockets created by tainted processes.
            realm_init_socket(inode_data);
        }
    }
    return 0;
}


/*
 *	Check permissions before creating a fresh pair of sockets.
 *	@socka contains the first socket structure.
 *	@sockb contains the second socket structure.
 *	Return 0 if permission is granted and the connection was established.
 */
int trm_socket_socketpair(struct socket *socka, struct socket *sockb) {
    struct inode *s_inode_a = SOCK_INODE(socka);
    struct inode *s_inode_b = SOCK_INODE(sockb);
    citadel_inode_data_t *inode_data_a = trm_inode(s_inode_a);
    citadel_inode_data_t *inode_data_b = trm_inode(s_inode_b);
    citadel_task_data_t *task_data = citadel_cred(current_cred());
    task_housekeeping();

    // TODO fix
    if (inode_data_a && (inode_data_a->in_realm || task_data->in_realm)) {
        realm_init_socket(inode_data_a);
        realm_init_socket_copy(inode_data_a, inode_data_b);
        // return can_access(s_inode_a, CITADEL_OP_SOCKET_INTERNAL);
    }
    return 0;
}


/*
 *	Check permission before socket protocol layer bind operation is
 *	performed and the socket @sock is bound to the address specified in the
 *	@address parameter.
 *	@sock contains the socket structure.
 *	@address contains the address to bind to.
 *	@addrlen contains the length of address.
 *	Return 0 if permission is granted.
 */
int trm_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen) {
    struct inode *s_inode = SOCK_INODE(sock);
    citadel_inode_data_t *inode_data = trm_inode(s_inode);
    citadel_task_data_t *task_data = citadel_cred(current_cred());
    task_housekeeping();

    if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
        realm_init_socket(inode_data);
        if (address->sa_family == AF_UNIX || address->sa_family == AF_LOCAL) {
            // This is a local socket, and therefore governed by permission on the inode.
            printk(PFX "Tainted socket/process tried to bind -- internal (%d).\n", address->sa_family);
            return 0; //can_access(s_inode, CITADEL_OP_SOCKET_INTERNAL);
        } else {
            // This is external.
            printk(PFX "Tainted socket/process tried to bind -- external (%d).\n", address->sa_family);
            return can_access(s_inode, CITADEL_OP_SOCKET_EXTERNAL);
        }
    }
    return 0;
}

/*
 *	Check permission before accepting a new connection.  Note that the new
 *	socket, @newsock, has been created and some information copied to it,
 *	but the accept operation has not actually been performed.
 *	@sock contains the listening socket structure.
 *	@newsock contains the newly created server socket for connection.
 *	Return 0 if permission is granted.
 */
int trm_socket_accept(struct socket *sock, struct socket *newsock) {
    struct inode *s_inode = SOCK_INODE(sock);
    struct inode *s_inode_new = SOCK_INODE(newsock);
    citadel_inode_data_t *inode_data = trm_inode(s_inode);
    citadel_inode_data_t *inode_data_new = trm_inode(s_inode_new);
    citadel_task_data_t *task_data = citadel_cred(current_cred());
    task_housekeeping();

    if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
        realm_init_socket(inode_data);
        realm_init_socket_copy(inode_data, inode_data_new);
        return can_access(s_inode, CITADEL_OP_SOCKET);
    }
    return 0;
}

/*
 *	Check permission before transmitting a message to another socket.
 *	@sock contains the socket structure.
 *	@msg contains the message to be transmitted.
 *	@size contains the size of message.
 *	Return 0 if permission is granted.
 */
int trm_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size) {
    struct inode *s_inode = SOCK_INODE(sock);
    citadel_inode_data_t *inode_data = trm_inode(s_inode);
    citadel_task_data_t *task_data = citadel_cred(current_cred());
    task_housekeeping();

    if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
        realm_init_socket(inode_data);
        return can_access(s_inode, CITADEL_OP_SOCKET);
    }
    return 0;
}


/*
 *	Check permission before receiving a message from a socket.
 *	@sock contains the socket structure.
 *	@msg contains the message structure.
 *	@size contains the size of message structure.
 *	@flags contains the operational flags.
 *	Return 0 if permission is granted.
 */
int trm_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags) {
    struct inode *s_inode = SOCK_INODE(sock);
    citadel_inode_data_t *inode_data = trm_inode(s_inode);
    citadel_task_data_t *task_data = citadel_cred(current_cred());
    task_housekeeping();

    if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
        realm_init_socket(inode_data);
        return can_access(s_inode, CITADEL_OP_SOCKET);
    }
    return 0;
}


/*
 *	Checks permission before all or part of a connection on the socket
 *	@sock is shut down.
 *	@sock contains the socket structure.
 *	@how contains the flag indicating how future sends and receives
 *	are handled.
 *	Return 0 if permission is granted.
 */
int trm_socket_shutdown(struct socket *sock, int how) {
    struct inode *s_inode = SOCK_INODE(sock);
    citadel_inode_data_t *inode_data = trm_inode(s_inode);
    citadel_task_data_t *task_data = citadel_cred(current_cred());
    task_housekeeping();

    if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
        printk(PFX "PID %d shutting down socket %ld (how: %d)\n", current->pid, s_inode->i_ino, how);
    }

    return 0;
}