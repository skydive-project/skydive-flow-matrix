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

    for socket in node.metadata["Sockets"]:
        if socket["LocalAddress"] == local_addr and socket["LocalPort"] == local_port:
            return socket


def flow_matrix(restclient):

    # get all the sockets informations
    host_nodes = restclient.lookup_nodes(
        "G.V().Has('Type', 'host').HasKey('Sockets')")
    if not host_nodes:
        return

    # list all the LISTEN sockets
    listen_ports = set()
    for node in host_nodes:
        for socket in node.metadata["Sockets"]:
            if socket["State"] == "LISTEN":
                listen_ports.add(socket["LocalPort"])

    matrix = set()

    for node in host_nodes:
        for socket in node.metadata["Sockets"]:
            # report UDP listen sockets
            if socket["Protocol"] == "UDP" and socket["State"] == "CLOSE":
                matrix.add(','.join([
                    socket["Protocol"], node.host, socket["LocalAddress"],
                    str(socket["LocalPort"]), socket["Process"], socket["Name"]
                ]))
            # get server side connections so having LocalPort listenning
            elif socket["State"] == "ESTABLISHED" and socket["LocalPort"] in listen_ports:
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
                    matrix.add(','.join([
                          socket["Protocol"], node.host,
                          socket["LocalAddress"],
                          str(socket["LocalPort"]), socket["Process"],
                          socket["Name"], peer.host, socket["RemoteAddress"],
                          socket_peer["Process"], socket_peer["Name"]
                      ]))
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

    args = parser.parse_args()

    scheme = "http"
    if args.ssl:
        scheme = "https"

    restclient = RESTClient(args.analyzer, scheme=scheme, insecure=args.insecure, 
                            username=args.username, password=args.password)
    matrix = flow_matrix(restclient)

    print("protocol,server,server_ip,port,server_proc,server_procname,"
          "client,client_ip,client_proc,client_procname")
    for e in matrix:
        print(e)


if __name__ == '__main__':
    main()
