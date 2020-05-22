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
    citadel_task_data_t *task_data = trm_cred(current_cred());
    if (inode_data) {
        inode_data->is_socket = true;
        inode_data->checked_disk_xattr = true;
        if (task_data->in_realm) {
            // Automatically restrict sockets created by tainted processes.
            inode_data->in_realm = true;
            get_random_bytes(inode_data->identifier, _CITADEL_IDENTIFIER_LENGTH);
            printk(PFX "Socket created by tainted process, set in_realm (%ld)\n", s_inode->i_ino);
        }
    }
    return 0;
}

int trm_socket_socketpair(struct socket *socka, struct socket *sockb) {
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
    citadel_task_data_t *task_data = trm_cred(current_cred());
    if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
        if (address->sa_family == AF_UNIX || address->sa_family == AF_LOCAL) {
            // This is a local socket, and therefore governed by permission on the inode.
            printk(PFX "Tainted socket/process tried to bind -- internal.\n");
            return can_access(inode_data, CITADEL_OP_SOCKET_INTERNAL);
        } else {
            // This is external.
            printk(PFX "Tainted socket/process tried to bind -- external.\n");
            return can_access(inode_data, CITADEL_OP_SOCKET_EXTERNAL);
        }
    }
    return 0;
}