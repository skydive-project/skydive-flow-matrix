#!/usr/bin/python

import argparse
import logging
import subprocess
import sys
import time
import unittest

from skydive.graph import Node
from skydive.rest.client import RESTClient


def get_socket(node, local_addr, local_port):

    if "Sockets" not in node.metadata:
        return
    for socket in node.metadata["Sockets"]:
        if socket["LocalAddress"] == local_addr and socket["LocalPort"] == local_port:
            return socket


def get_node_by_addr(restclient, address, node_cache):
    node = None

    if address in node_cache:
        return node_cache[address]
    nodes = restclient.lookup_nodes(
        "G.V().Has('IPV4', IPV4Range('%s/32')).In('Type', 'host')" % address)
    if len(nodes) > 0:
        node = nodes[0]
        node_cache[address] = node
    return node


def is_listen_socket(socket):
    return (socket["State"] == "LISTEN" or (
            (socket["Protocol"] == "UDP" and
             socket["State"] == "CLOSE" and
             (socket["RemoteAddress"] == "0.0.0.0" or
              socket["RemoteAddress"] == "::"))))


def flow_matrix(restclient, listen_ports, matrix):

    sockets = restclient.lookup("G.Flows().Has('Transport', NE('')).Sockets()")
    if sockets:
        host_cache = {}

        for flow_id, entries in sockets[0].items():
            # read both ends of the flow
            for socket in entries:
                if socket["State"] != "ESTABLISHED":
                    break

                if socket["RemotePort"] in listen_ports:
                    server_address = socket["RemoteAddress"]
                    server_port = socket["RemotePort"]

                    # get server node
                    node = get_node_by_addr(restclient, server_address,
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
                    client_port = socket["LocalPort"]

                    node = get_node_by_addr(restclient,
                                            client_address, host_cache)
                    if not node:
                       continue

                    client = node.host
                    client_proc = socket["Process"]
                    client_proc_name = socket["Name"]

                    matrix.add(','.join([
                                   socket["Protocol"], server, server_address,
                                   str(server_port), server_proc,
                                   server_proc_name, client, client_address,
                                   client_proc, client_proc_name]))


def topology_matrix(restclient, host_nodes, listen_ports, matrix):

    for node in host_nodes:
        for socket in node.metadata["Sockets"]:
            # get server side connections so having LocalPort listenning
            if (socket["State"] == "ESTABLISHED" and
                socket["LocalPort"] in listen_ports):

                # find the other side of the connections in order to get the process
                query = (
                    "G.V().Has('Sockets.State', 'ESTABLISHED')."
                    "Has('Sockets.LocalAddress', '%s', 'Sockets.LocalPort', %s, "
                    "'Sockets.RemoteAddress', '%s', 'Sockets.RemotePort', %s)"
                ) % (socket["RemoteAddress"], socket["RemotePort"],
                     socket["LocalAddress"], socket["LocalPort"])
                peers = restclient.lookup_nodes(query)

                if len(peers) > 0:
                    peer = peers[0]
                    socket_peer = get_socket(peer, socket["RemoteAddress"],
                                             socket["RemotePort"])
                    # workaround, check both integer value plus string until
                    # we fix the protocol format flapping issue
                    protocol = "UDP"
                    if socket["Protocol"] == 2 or socket["Protocol"] == "TCP":
                        protocol = "TCP"

                    matrix.add(','.join([
                          protocol, node.host,
                          socket["LocalAddress"],
                          str(socket["LocalPort"]), socket["Process"],
                          socket["Name"], peer.host, socket["RemoteAddress"],
                          socket_peer["Process"], socket_peer["Name"]
                      ]))
    return matrix


def matrix(restclient, use_flows=False):

    # get all the sockets informations
    host_nodes = restclient.lookup_nodes(
        "G.V().Has('Type', 'host').HasKey('Sockets')")
    if not host_nodes:
        return

    # list all the LISTEN sockets and their nodes
    listen_ports = set()
    for node in host_nodes:
        for socket in node.metadata["Sockets"]:
            if is_listen_socket(socket):
               listen_ports.add(socket["LocalPort"])

    matrix = set()

    topology_matrix(restclient, host_nodes, listen_ports, matrix)
    if use_flows:
        flow_matrix(restclient, listen_ports, matrix)

    return matrix


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


    args = parser.parse_args()

    scheme = "http"
    if args.ssl:
        scheme = "https"

    restclient = RESTClient(args.analyzer, scheme=scheme, insecure=args.insecure, 
                            username=args.username, password=args.password)
    result = matrix(restclient, args.use_flows)

    print("protocol,server,server_ip,port,server_proc,server_procname,"
          "client,client_ip,client_proc,client_procname")
    for e in result:
        print(e)


if __name__ == '__main__':
    main()
