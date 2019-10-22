#!/usr/bin/python

#
# Copyright (C) 2018 Red Hat, Inc.
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import argparse
import ipaddress
import uuid
import sys

from graphviz import Digraph
from os import environ

from skydive.graph import Node, Edge
from skydive.rest.client import RESTClient
from skydive.websocket.client import WSClient
from skydive.websocket.client import WSClientDebugProtocol
from skydive.websocket.client import WSMessage
from skydive.websocket.client import NodeAddedMsgType, EdgeAddedMsgType


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


def is_loop_back(addr):
    ip = ipaddress.ip_address(addr)
    return ip.is_loopback


class MatrixEntry:
    def __init__(self, protocol, service_host, service_address,
                 service_port, service_process, service_name,
                 client_host, client_address, client_process,
                 client_name):

        self.protocol = protocol
        self.service_host = service_host
        self.service_address = service_address
        self.service_port = service_port
        self.service_process = service_process
        self.service_name = service_name
        self.client_host = client_host
        self.client_address = client_address
        self.client_process = client_process
        self.client_name = client_name

    def __eq__(self, other):
        if isinstance(other, MatrixEntry):
            return (self.__hash__() == self.__hash__())
        else:
            return False

    def __repr__(self):
        return ','.join([self.protocol, self.service_host,
                         self.service_address, str(self.service_port),
                         self.service_process, self.service_name,
                         self.client_host, self.client_address,
                         self.client_process, self.client_name])

    def __hash__(self):
        return hash(self.__repr__())


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

    def get_socket_peer(self, sockets, protocol, local_addr, local_port, from_node):
        if local_port not in sockets.keys():
            return
        for socket in sockets[local_port]:
            s = socket["socket"]
            if is_loop_back(local_addr):
                if (s["Protocol"] == protocol and s["LocalAddress"] == local_addr and
                    s["LocalPort"] == local_port and socket["node"].host == from_node.host):
                    return socket
            elif (s["Protocol"] == protocol and s["LocalAddress"] == local_addr and
                    s["LocalPort"] == local_port):
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

        for _, entries in sockets[0].items():
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

                    entry = MatrixEntry(
                        socket["Protocol"],
                        server,
                        server_address,
                        str(server_port),
                        server_proc,
                        server_proc_name,
                        client,
                        client_address,
                        client_proc,
                        client_proc_name
                    )
                    self.matrix.add(entry)

    def topology_matrix(self, host_nodes, listen_ports, peer_sockets):
        for node in host_nodes:
            for socket in node.metadata["Sockets"]:
                # get server side connections so having LocalPort listenning
                if (socket["RemotePort"] in listen_ports and
                    (socket["State"] == "ESTABLISHED" or
                     (self.at and not is_listen_socket(socket)))):

                    peer = self.get_socket_peer(peer_sockets,
                                                socket["Protocol"],
                                                socket["RemoteAddress"],
                                                socket["RemotePort"],
                                                node)
                    if not peer:
                        cnx = {"node": node, "socket": socket}
                        if cnx not in self.unknown_cnx:
                            self.unknown_cnx.append(cnx)
                        continue
                    socket_peer = peer["socket"]

                    entry = MatrixEntry(
                        socket["Protocol"],
                        peer["node"].host,
                        socket["RemoteAddress"],
                        socket["RemotePort"],
                        socket_peer["Process"],
                        socket_peer["Name"],
                        node.host,
                        socket["LocalAddress"],
                        socket["Process"],
                        socket["Name"]
                    )
                    self.matrix.add(entry)


def csv_output(matrix, list_no_peers=False):
    result = matrix.get_matrix()
    if result is None:
        print("No result, please check analyzer address")
        return

    print("protocol,server,server_ip,port,server_proc,server_procname,"
          "client,client_ip,client_proc,client_procname")
    for e in result:
        print(e)

    if list_no_peers:
        print("peer not found for connection:")
        for cnx in matrix.unknown_cnx:
            socket = cnx["socket"]
            print(socket["Protocol"], cnx["node"].host,
                  socket["RemotePort"], socket)


def dot_output(matrix, engine, render):
    result = matrix.get_matrix()
    if result is None:
        print("No result, please check analyzer address")
        return

    g = Digraph(comment='Skydive Flow matrix repport', engine=engine)
    g.attr(overlap='false')
    g.attr(ranksep='1')
    g.attr(nodesep='0.7')

    endpoints = {}
    for entry in result:
        if entry.service_host in endpoints:
            endpoints[entry.service_host].add(entry.service_name)
        else:
            endpoints[entry.service_host] = set([entry.service_name])

        if entry.client_host in endpoints:
            endpoints[entry.client_host].add(entry.client_name)
        else:
            endpoints[entry.client_host] = set([entry.client_name])

    for k, v in endpoints.iteritems():
        with g.subgraph(name='cluster_' + k) as c:
            c.body.append('label="' + k + '"')
            c.body.append('fontsize="24"')
            c.body.append('color="gray50"')
            c.body.append('style="filled"')
            c.body.append('fillcolor="gray90"')

            for name in v:
                c.node(k+name, label=name+'\\n\\n'+k, shape='component', color='orangered', fillcolor='orange', style='filled')

    for entry in result:
        g.edge(entry.client_host+entry.client_name,
               entry.service_host+entry.service_name,
               label=(entry.protocol + " : " +
                      entry.service_address + ":" +
                      str(entry.service_port)))

    if render:
        if environ.get('DISPLAY') is None:
            print("skydive-flow-matrix need run on pc with GUI")
            sys.exit()
        g.view()
    else:
        print(g.source)

class WSMatrixProtocol(WSClientDebugProtocol):

    def onOpen(self):
        result = self.factory.kwargs["result"]

        endpoints = {}
        for entry in result:
            if entry.service_host in endpoints:
                endpoints[entry.service_host].add(entry.service_name)
            else:
                endpoints[entry.service_host] = set([entry.service_name])

            if entry.client_host in endpoints:
                endpoints[entry.client_host].add(entry.client_name)
            else:
                endpoints[entry.client_host] = set([entry.client_name])

        for k, v in endpoints.iteritems():
            """
            hid = uuid.uuid5(uuid.NAMESPACE_DNS, str(k))
            node = Node(str(hid), k, metadata={"Name": k, "Type": "host"})
            msg = WSMessage("Graph", NodeAddedMsgType, node)

            self.sendWSMessage(msg)
            """
            for name in v:
                nid = uuid.uuid5(uuid.NAMESPACE_DNS, str(k+name))
                node = Node(str(nid), k, metadata={"Name": name, "Type": "service"})
                msg = WSMessage("Graph", NodeAddedMsgType, node)
                self.sendWSMessage(msg)

                """
                edge = Edge(str(uuid.uuid1()), k, str(hid), str(nid),
                            metadata={"RelationType": "ownership"})
                msg = WSMessage("Graph", EdgeAddedMsgType, edge)
                self.sendWSMessage(msg)
                """

        for entry in result:
            try:
                nid1 = uuid.uuid5(uuid.NAMESPACE_DNS, str(entry.client_host+entry.client_name))
                nid2 = uuid.uuid5(uuid.NAMESPACE_DNS, str(entry.service_host+entry.service_name))
                edge = Edge(str(uuid.uuid1()), k, str(nid1), str(nid2),
                            metadata={"RelationType": "layer2", "Type": "Connection"})
                msg = WSMessage("Graph", EdgeAddedMsgType, edge)
                self.sendWSMessage(msg)
            except Exception as e:
                print(e)

        #self.stop()

def skydive_output(matrix):
    result = matrix.get_matrix()
    if result is None:
        print("No result, please check analyzer address")
        return

    client = WSClient('localhost', 'ws://localhost:8082/ws/publisher',
                      protocol=WSMatrixProtocol,
                      result=result)

    client.connect()
    client.start()


def main():

    parser=argparse.ArgumentParser()
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
    parser.add_argument('--format', default="csv",
                        dest='format', choices=['csv', 'dot', 'render', 'skydive'],
                        help="specify the output format")
    parser.add_argument('--engine', default="dot",
                        dest='engine', choices=['dot', 'circo', 'neato'],
                        help="specify the rendering engine")

    args=parser.parse_args()

    scheme="http"
    if args.ssl:
        scheme="https"

    restclient=RESTClient(args.analyzer, scheme=scheme, insecure=args.insecure,
                            username=args.username, password=args.password)
    matrix=Matrix(restclient, args.use_flows, args.at, args.duration)

    if args.format == "dot" or args.format == "render":
        dot_output(matrix, args.engine, args.format == "render")
    elif args.format == "skydive":
        skydive_output(matrix)
    else:
        csv_output(matrix, args.list_no_peers)


if __name__ == '__main__':
    main()
