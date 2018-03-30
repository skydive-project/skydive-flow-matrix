#!/usr/bin/python

import argparse

from skydive.rest.client import RESTClient


def get_socket(node, local_addr, local_port):
    if "Sockets" not in node.metadata:
        return
    for socket in node.metadata["Sockets"]:
        if socket["LocalAddress"] == local_addr and socket["LocalPort"] == local_port:
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

    def get_matrix(self):
        # get all the sockets informations
        host_nodes = self.restclient.lookup_nodes(
            "G.V().Has('Type', 'host').HasKey('Sockets')")
        if not host_nodes:
            return

        # list all the LISTEN sockets and their nodes
        listen_ports = set()
        for node in host_nodes:
            for socket in node.metadata["Sockets"]:
                if is_listen_socket(socket):
                    listen_ports.add(socket["LocalPort"])

        self.matrix = set()

        self.topology_matrix(host_nodes, listen_ports)
        if self.use_flows:
            self.flow_matrix(listen_ports)

        return self.matrix

    def get_context(self):
        if self.at == "":
            return ""
        if self.duration == 0:
            return "Context('%s')." % self.at
        return "Context('%s', %d)." % (self.at, self.duration)

    def get_node_by_addr(self, address, node_cache):
        node = None

        if address in node_cache:
            return node_cache[address]
        nodes = self.restclient.lookup_nodes(
            "G.%sV().Has('IPV4', IPV4Range('%s/32')).In('Type', 'host')" %
            (self.get_context(), address))
        if len(nodes) > 0:
            node = nodes[0]
            node_cache[address] = node
        return node

    def flow_matrix(self, listen_ports):
        sockets = self.restclient.lookup(
            "G.%sFlows().Has('Transport', NE('')).Sockets()" %
            self.get_context())
        if sockets:
            host_cache = {}

        for flow_id, entries in sockets[0].items():
            # read both ends of the flow
            for socket in entries:
                if socket["RemotePort"] in listen_ports:
                    server_address = socket["RemoteAddress"]
                    server_port = socket["RemotePort"]

                    # get server node
                    node = self.get_node_by_addr(server_address,
                                                 host_cache)
                    if not node:
                        break

                    server_socket = get_socket(node,
                                               server_address, server_port)
                    if not server_socket:
                        break

                    server = node.host
                    server_proc = server_socket["Process"]
                    server_proc_name = server_socket["Name"]

                    client_address = socket["LocalAddress"]
                    node = self.get_node_by_addr(client_address, host_cache)
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

    def topology_matrix(self, host_nodes, listen_ports):
        for node in host_nodes:
            for socket in node.metadata["Sockets"]:
                # get server side connections so having LocalPort listenning
                if ((socket["State"] == "ESTABLISHED" or self.at) and
                    socket["LocalPort"] in listen_ports):

                    # find the other side of the connections in order to get the process
                    query = "G.%sV()." % self.get_context()
                    if not self.at:
                        query += "Has('Sockets.State', 'ESTABLISHED')."
                    query += ("Has('Sockets.LocalAddress', '%s', 'Sockets.LocalPort', %s, " +
                              "'Sockets.RemoteAddress', '%s', 'Sockets.RemotePort', %s)"
                    ) % (socket["RemoteAddress"], socket["RemotePort"],
                         socket["LocalAddress"], socket["LocalPort"])
                    peers = self.restclient.lookup_nodes(query)

                    if len(peers) > 0:
                        peer = peers[0]
                        socket_peer = get_socket(peer, socket["RemoteAddress"],
                                                 socket["RemotePort"])
                        if not socket_peer:
                            continue
                        # workaround, check both integer value plus string until
                        # we fix the protocol format flapping issue
                        #    protocol = "UDP"
                        #    if socket["Protocol"] == 2 or socket["Protocol"] == "TCP":
                        #        protocol = "TCP"
                        protocol = socket["Protocol"]

                        self.matrix.add(','.join([
                            protocol, node.host,
                            socket["LocalAddress"],
                            str(socket["LocalPort"]), socket["Process"],
                            socket["Name"], peer.host, socket["RemoteAddress"],
                            socket_peer["Process"], socket_peer["Name"]
                        ]))
                    return self.matrix


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


if __name__ == '__main__':
    main()
