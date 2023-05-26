import matplotlib.pyplot as plt
from config import *
import networkx as nx
from dijkstar import Graph, find_path
from utils import json_get_req, json_post_req
import json
import logging
import time
import numpy as np
import pandas as pd
import random
import operator


class TopoManager(object):
    
    def __init__(self):
        self.graph = nx.Graph()
        self.graphDijkstar = Graph()
        self.is_congestion = False
        # arguments for drawing topology
        self.__pos = None
        self.__hosts = []
        self.__devices = []

    def get_hosts(self):
        reply = json_get_req('http://%s:%d/getHosts' % (ONOS_IP, ONOS_PORT))
        self.__hosts = []
        for host in reply["hosts"]:
            self.__hosts.append(host['host'])
        return self.__hosts

    def get_number_hosts(self):
        if self.is_topo_available():
            return len(self.__hosts)
        return 0

        
    def is_topo_available(self):
        reply = json_get_req('http://%s:%d/state/bandwidth' % (ONOS_IP, ONOS_PORT))
        if isinstance(reply, str) or reply['links'] == []:
            logging.info("[Warning] topology error: %s", reply)
            return False
        return True


    def draw_topo(self, block=True):
        self.__pos = nx.fruchterman_reingold_layout(self.graph)      
        plt.figure()
        nx.draw_networkx_nodes(self.graph, self.__pos, nodelist=self.__hosts, node_shape='o', node_color='w')
        nx.draw_networkx_nodes(self.graph, self.__pos, nodelist=self.__devices, node_shape='s', node_color='b')
        nx.draw_networkx_labels(self.graph.subgraph(self.__hosts), self.__pos, font_color='k')
        nx.draw_networkx_labels(self.graph.subgraph(self.__devices), self.__pos, font_color='k')
        nx.draw_networkx_edges(self.graph, self.__pos)
        plt.show(block=block)

class StatisticsAndRuleManager(object):

    def __init__(self):
        self.graphDijkstar = Graph()
        self.__conns = []
        self.__reroute_msg = {'paths': []}


    def getconnsbandwidth(self):
        conns = []
        prev_stats = json_get_req('http://%s:%d/state/connsbandwidth' % (ONOS_IP, ONOS_PORT))
        time.sleep(STATISTICS_INTERVAL)
        next_stats = json_get_req('http://%s:%d/state/connsbandwidth' % (ONOS_IP, ONOS_PORT))
        for prev_stat, next_stat in zip(prev_stats['connectivities'],next_stats['connectivities']):
            n1 = prev_stat['Src']
            n2 = prev_stat['Dst']
            flowid = prev_stat['flowid']
            delta_time = next_stat['life'] - prev_stat['life']
            delta_byte = next_stat['byte'] - prev_stat['byte']
            bw = 0
            if delta_time > 0 and delta_byte > 0:
                bw = (delta_byte / delta_time) * 8 / 1000  # unit: Kbps
            self.__add_conn_pair(conns, n1, n2, bw,flowid)
        return conns


    def __add_conn_pair(self, conns, n1, n2, bw, appid):
        i = 0
        sum_= 0;
        conns.append({'Src': n1, 'Dst': n2, 'bw': bw})
        return

    def getLinkStatistics(self):
        linkStats = []
        # get bandwidth
        reply_bw = json_get_req('http://%s:%d/state/bandwidth' % (ONOS_IP, ONOS_PORT))
        reply_latency = json_get_req('http://%s:%d/state/latency' % (ONOS_IP, ONOS_PORT))

        maxdij = 0
        for link_latency in reply_latency['links']:
            if  link_latency['latency']> maxdij:
                maxdij = link_latency['latency']
        if maxdij == 0: # avoid NaN values in normalization
            maxdij = 1

        for link_bw  in reply_bw['links']:
            for link_latency in reply_latency['links']:
                if link_bw['src']==link_latency['src'] and link_bw['dst']==link_latency['dst']:
                    uij = link_bw['bw']/LINK_BANDWIDTH_LIMIT  # normalized bw utilization
                    dij = link_latency['latency']/maxdij      # normalized delay
                    linkStats.append({'Src': link_bw['src'], 'Dst': link_bw['dst'], 'bw': uij, 'latency': dij})

        return (linkStats)

    def shadowServerSelection(self, location_attacker, location_shadow_servers):
        # get link statics
        linkStats = self.getLinkStatistics()

        # build graph
        for i in range(0, len(linkStats)):
            n1 = linkStats[i]['Src']
            n2 = linkStats[i]['Dst']
            bw = linkStats[i]['bw'] # unit: Kbps
            ltc = linkStats[i]['latency'] # unit: Kbps
            self.graphDijkstar.add_edge(n1 , n2, bw + ltc)

        # find sortest paths btwn attacker and shadow servers
        cost = [0]*len(location_shadow_servers)
        for i in range(len(location_shadow_servers)):
            result  = find_path(self.graphDijkstar, location_attacker, location_shadow_servers[i])
            cost[i] = getattr( result, 'total_cost')

        # Digital Fountain
        divisor = sum(cost)
        if divisor > 0:
            # formula of digital fountain
            P = np.array(cost)/divisor
            # TODO roulete
            sorted_indexed_p = sorted(enumerate(P), key=operator.itemgetter(1))
            indices, sorted_p = zip(*sorted_indexed_p);

            # calculate the cumulative probability
            cum_prob=np.cumsum(sorted_p)
            # select a random a number in the range [0,1]
            random_num=random.random()

            for index_value, cum_prob_value in zip(indices,cum_prob):
                if random_num < cum_prob_value:
                    return index_value
        else:
            P = random.randint(0,len(location_shadow_servers)-1)

        return P


    def reroute(self, topo):
        self.__conns = self.__get_conns()
        logging.info("Start finding path between two hosts...")
        for conn in self.__conns:
            _topo = topo
            n1 = conn['one']
            n2 = conn['two']
            bw = conn['bw']
            logging.info("[%s, %s] %s (Kbps)", n1, n2, bw)
            while True:
                path, reduced_topo = self.__find_path(n1, n2, bw, _topo)
                if reduced_topo == None:
                    # found no path in this connectivity; do nothing
                    break
                elif path == None:
                    # found path that has insufficient capacity; find another path on reduced topology
                    _topo = reduced_topo
                    continue
                else:
                    self.__reroute_msg['paths'].append({'path': path})
                    topo = self.__reduce_capacity_on_path(path, topo, bw)
                    break
        self.__send_paths(self.__reroute_msg)
        
    def __find_path(self, n1, n2, bw, topo):
        try:
            reduced_topo = topo.copy()
            is_bad_path = False
            path = nx.shortest_path(reduced_topo, n1, n2)
            for link in zip(path, path[1:]):
                src = link[0]
                dst = link[1]
                reduced_topo[src][dst]['bandwidth'] -= bw
                if reduced_topo[src][dst]['bandwidth'] <= 0:
                    reduced_topo.remove_edge(src, dst)
                    is_bad_path = True              
            if is_bad_path == True:
                return (None, reduced_topo)
            else:
                return (path, reduced_topo)
        except nx.NetworkXNoPath:
            logging.info("[Warning] no path found: %s, %s", n1, n2)
            return (None, None)

    def __reduce_capacity_on_path(self, path, reduced_topo, bw):
        for link in zip(path, path[1:]):
            src = link[0]
            dst = link[1]
            reduced_topo[src][dst]['bandwidth'] -= bw
        return reduced_topo
   
    def __send_paths(self, reroute_msg):
        routes = reroute_msg['paths']
        if routes == []:
            logging.info("[Warning] no paths to send")
            return
        # add paths in reverse direction
        reversed_paths = []
        for route in routes:
            reversed_path = {'path': route['path'][::-1]}
            if reversed_path not in routes and reversed_path not in reversed_paths:  
                reversed_paths.append(reversed_path)
        routes.extend(reversed_paths)   
        # send paths for rerouting   
        logging.info("Start rerouting...")
        for msg in reroute_msg['paths']:
            logging.info(msg['path'])
        reply = json_post_req('http://%s:%d/reroute' % (ONOS_IP, ONOS_PORT), json.dumps(reroute_msg))
        if reply != '':
            logging.info(reply)

    def dropCommand(self, dropping):
        # send host for dropping   
        reply = json_post_req('http://%s:%d/dropping' % (ONOS_IP, ONOS_PORT), json.dumps(dropping))
        if reply != '':
            logging.error(reply)

    def removeDropCommand(self, removeDrop):
        # send host to remove dropping rules
        reply = json_post_req('http://%s:%d/removeBlockRules' % (ONOS_IP, ONOS_PORT), json.dumps(removeDrop))
        if reply != '':
            logging.warning(reply)


    def removeMTDCommand(self, attacker, shadow_servers):
        # send host to remove dropping rules
        removeMTP = {}
        removeMTP["ss1"] =  {'macsrc': attacker, 'macdst':shadow_servers[0]}
        removeMTP["ss2"] =  {'macsrc': attacker, 'macdst':shadow_servers[1]}
        reply = json_post_req('http://%s:%d/removeSNATRules' % (ONOS_IP, ONOS_PORT), json.dumps(removeMTP))
        if reply != '':
            logging.warning(reply)

    def reroutingCommand(self, rerouting):
        # send host for dropping   
        reply = json_post_req('http://%s:%d/rerouting' % (ONOS_IP, ONOS_PORT), json.dumps(rerouting))
        if reply != '':
            logging.info(reply)

    def movingTargetDefense(self, macattacker, macoriginal_server, macshadow_servers):
        # locate attacker
        temp = {}
        temp[macattacker] = {"macHost": macattacker}
        location_attacker = json_post_req('http://%s:%d/getHostLocation' % (ONOS_IP, ONOS_PORT), json.dumps(temp))
        location_attacker = location_attacker['locations'][0]['location']

        # locate shadow servers
        temp = {}
        for i in range(len(macshadow_servers)):
            temp[macshadow_servers[i]]={"macHost": macshadow_servers[i]}
        reply_shadow_servers = json_post_req('http://%s:%d/getHostLocation' % (ONOS_IP, ONOS_PORT), json.dumps(temp))
        location_shadow_servers = []
        for reply_shadow_server in reply_shadow_servers['locations']:
            location_shadow_servers.append(reply_shadow_server['location'])

        # select shadow server
        macshadow_server = macshadow_servers[self.shadowServerSelection(location_attacker, location_shadow_servers)]
        
        # build data to send
        moving_target_defense = {}    
        moving_target_defense[macattacker+' to '+macshadow_server]={'macattacker': macattacker, 'macserver': macoriginal_server,'macshadowserver': macshadow_server}

        # send host for moving target defense 
        logging.info("[IPS] MTD Src: %s  Dst: %s",macattacker, macshadow_server)   
        reply = json_post_req('http://%s:%d/movingTargetDefense' % (ONOS_IP, ONOS_PORT), json.dumps(moving_target_defense))
        if reply != '':
            logging.warning(reply)

    def resetCommand(self, resetConnection):
        # send host for dropping   
        reply = json_post_req('http://%s:%d/resetCommunication' % (ONOS_IP, ONOS_PORT), json.dumps(resetConnection))
        if reply != '':
            logging.warning(reply)
