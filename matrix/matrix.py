#!/usr/bin/python

import argparse

from skydive.rest.client import RESTClient


def get_socket(node, protocol, local_addr, local_port):
    if "Sockets" not in node.metadata:
        return
    for socket in node.metadata["Sockets"]:
        if (socket["Protocol"] == protocol and
            socket["LocalAddress"] == local_addr and
            socket["LocalPort"] == local_port):
            return socket

def is_listen_socket(socket):
    return (socket["State"] == "LISTEN" or (
            (socket["Protocol"] == "UDP" and
             socket["State"] == "CLOSE" and
             (socket["RemoteAddress"] == "0.0.0.0" or
              socket["RemoteAddress"] == "::"))))


class Matrix:
    def __init__(self, restclient, use_flows=False, at="", duration=0):
        self.restclient = restclient
        self.use_flows = use_flows
        self.at = at
        self.duration = duration
        self.unknown_cnx = []
        self.host_cache = {}

    def get_matrix(self):
        # get all the sockets informations
        host_nodes = self.restclient.lookup_nodes(
            "G.%sV().Has('Type', 'host').HasKey('Sockets')" % self.get_context())
        if not host_nodes:
            return

        # list all the LISTEN sockets and their nodes
        listen_ports = set()
        peer_sockets = {}
        for node in host_nodes:
            for socket in node.metadata["Sockets"]:
                lport = socket["LocalPort"]
                if is_listen_socket(socket):
                    listen_ports.add(lport)
                else:
                    if lport not in peer_sockets:
                        peer_sockets[lport] = []
                    peer_sockets[lport].append(
                        {"node": node, "socket": socket}
                    )

        self.matrix = set()

        self.topology_matrix(host_nodes, listen_ports, peer_sockets)
        if self.use_flows:
            self.flow_matrix(listen_ports)

        return self.matrix

    def get_context(self):
        if self.at == "":
            return ""
        if self.duration == 0:
            return "Context('%s')." % self.at
        return "Context('%s', %d)." % (self.at, self.duration)

    def get_node_by_addr(self, address):
        node = None

        if address in self.host_cache:
            return self.host_cache[address]
        nodes = self.restclient.lookup_nodes(
            "G.%sV().Has('IPV4', IPV4Range('%s/32')).In('Type', 'host')" %
            (self.get_context(), address))
        if len(nodes) > 0:
            node = nodes[0]
            self.host_cache[address] = node
        return node
      
    def get_socket_peer(self, sockets, protocol, local_addr, local_port):
        if local_port not in sockets.keys():
            return
        for socket in sockets[local_port]:
            s = socket["socket"]
            if s["Protocol"] == protocol and s["LocalAddress"] == local_addr and s["LocalPort"] == local_port:
                return socket

        if protocol == "UDP":
            node = self.get_node_by_addr(local_addr)
            if not node:
                return
            for socket in node.metadata["Sockets"]:
                if (socket["Protocol"] == "UDP" and
                    is_listen_socket(socket) and
                    socket["LocalPort"] == local_port):
                    return {"node": node, "socket": socket}

    def flow_matrix(self, listen_ports):
        sockets = self.restclient.lookup(
            "G.%sFlows().Has('Transport', NE('')).Sockets()" %
            self.get_context())
        if sockets:
            self.host_cache = {}

        for flow_id, entries in sockets[0].items():
            # read both ends of the flow
            for socket in entries:
                if socket["RemotePort"] in listen_ports:
                    server_address = socket["RemoteAddress"]
                    server_port = socket["RemotePort"]

                    # get server node
                    node = self.get_node_by_addr(server_address)
                    if not node:
                        break

                    server_socket = get_socket(node,
                                               socket["Protocol"],
                                               server_address,
                                               server_port)
                    if not server_socket:
                        break

                    server = node.host
                    server_proc = server_socket["Process"]
                    server_proc_name = server_socket["Name"]

                    client_address = socket["LocalAddress"]
                    node = self.get_node_by_addr(client_address)
                    if not node:
                        continue

                    client = node.host
                    client_proc = socket["Process"]
                    client_proc_name = socket["Name"]

                    self.matrix.add(','.join([
                                   socket["Protocol"], server, server_address,
                                   str(server_port), server_proc,
                                   server_proc_name, client, client_address,
                                   client_proc, client_proc_name]))

    def topology_matrix(self, host_nodes, listen_ports, peer_sockets):
        for node in host_nodes:
            for socket in node.metadata["Sockets"]:
                # get server side connections so having LocalPort listenning
                if (socket["RemotePort"] in listen_ports and
                    (socket["State"] == "ESTABLISHED" or (self.at and not is_listen_socket(socket)))
                    ):

                    peer = self.get_socket_peer(peer_sockets,
                                                socket["Protocol"],
                                                socket["RemoteAddress"],	
                                                socket["RemotePort"])
                    if not peer:
                        cnx = {"node": node, "socket": socket}
                        if cnx not in self.unknown_cnx:
                            self.unknown_cnx.append(cnx)
                        continue
                    socket_peer = peer["socket"]

                    self.matrix.add(','.join([
                        socket["Protocol"], peer["node"].host,
                        socket["RemoteAddress"],
                        str(socket["RemotePort"]), socket_peer["Process"],
                        socket_peer["Name"], node.host, socket["LocalAddress"],
                        socket["Process"], socket["Name"]
                    ]))


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--analyzer', type=str, required=True,
                        dest='analyzer',
                        help='address of the Skydive analyzer')
    parser.add_argument('--username', type=str, default="",
                        dest='username',
                        help='client username')
    parser.add_argument('--password', type=str, default="",
                        dest='password',
                        help='client password')
    parser.add_argument('--ssl', default=False,
                        dest='ssl',
                        action="store_true",
                        help='use a secure SSL/TLS connection')
    parser.add_argument('--insecure', default=False,
                        dest='insecure',
                        action="store_true",
                        help="insecure connection, don't verify certificate")
    parser.add_argument('--use-flows', default=False,
                        dest='use_flows',
                        action="store_true",
                        help="leverages flows for matrix computing")
    parser.add_argument('--at', type=str, default="",
                        dest='at',
                        help='gremlin time at context')
    parser.add_argument('--duration', type=int, default=0,
                        dest='duration',
                        help='gremlin time duration context')
    parser.add_argument('--list-no-peers', default=False,
                        dest='list_no_peers',
                        action="store_true",
                        help="list connection peer not found/tracked by skydive")

    args = parser.parse_args()

    scheme = "http"
    if args.ssl:
        scheme = "https"

    restclient = RESTClient(args.analyzer, scheme=scheme, insecure=args.insecure,
                            username=args.username, password=args.password)
    matrix = Matrix(restclient, args.use_flows, args.at, args.duration)
    result = matrix.get_matrix()

    print("protocol,server,server_ip,port,server_proc,server_procname,"
          "client,client_ip,client_proc,client_procname")
    for e in result:
        print(e)

    if args.list_no_peers:
        print("peer not found for connection:")
        for cnx in matrix.unknown_cnx:
            socket = cnx["socket"]
            print(socket["Protocol"], cnx["node"].host, socket["RemotePort"], socket)

if __name__ == '__main__':
    main()
