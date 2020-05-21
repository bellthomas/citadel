
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
    citadel_task_data_t *task_data = trm_task(current_cred());
    if (inode_data) {
        inode_data->is_socket = true;
        if (task_data->in_realm) {
            // Automatically restrict sockets created by tainted processes.
            inode_data->in_realm = true;
            inode_data->needs_xattr_update = true;
        }
    }
    return 0;
}

int trm_socket_socketpair(struct socket *socka, struct socket *sockb) {
    return 0;
}