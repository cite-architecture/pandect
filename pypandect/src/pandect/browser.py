"""
copyright (c) 2014, Gabriel A. Weaver, Coordinated Science Laboratory 
at the University of Illinois at Urbana-Champaign.

This file is part of the Pandect Graph Browser distribution.

The code is free software:   you can redistribute 
it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version
3 of the License, or (at your option) any later version.

The Pandect Graph Browser distribution
is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License 
along with this program.  If not, see http://www.gnu.org/licenses/
"""
import cherrypy
import ConfigParser
import networkx as nx
import os, os.path
import json
import urllib
from networkx.readwrite import json_graph

from cptl import NMapDAO

class Browser(object):
    # Hardcoded stuff for PoC
    urn_prefix = "urn:nmap"
    host_id_prefix = "HOST_"

    """
    namespace_1 = "egCorp"
    networks_1 = "corporate"
    network_1 = "core"
    networks_urn_1 = ":".join([ urn_prefix, namespace_1, networks_1 ])
    network_urn_1 = ".".join([ networks_urn_1, network_1 ])
    """

    namespace_2 = "olympus"
    networks_2 = "HAN"
    network_2 = "pantheon"
    networks_urn_2 = ":".join([ urn_prefix, namespace_2, networks_2 ])
    network_urn_2 = ".".join([ networks_urn_2, network_2 ])
    
    nmDAO = None
    browser_graph = None

    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.readfp(open('config.cfg'))
        self.pandect_home_dir = config.get("basic","pandect_home_dir");
        self.pandect_src_dir = self.pandect_home_dir + "/src/pandect"
        self.pandect_data_dir = self.pandect_home_dir + "/data"
        self.nmap_input_data_path_1 = self.pandect_data_dir + "/test" + "/nmap/nmap-scan.1.xml"
        self.nmap_input_data_path_2 = self.pandect_data_dir + "/test" + "/nmap/nmap-scan.2.xml"


        self.nmDAO = NMapDAO.create( self.nmap_input_data_path_2,\
                                         "NMAP_XML",\
                                         self.network_urn_2,\
                                         self.host_id_prefix )
    
    @cherrypy.expose
    def index(self):
        return file(self.pandect_src_dir + "/public/html/index.html")

    @cherrypy.expose
    def _badger_get_host_dest_info(self, source_vertex_attr_value,\
                                       source_vertex_attr_type=None,\
                                       target_vertex_attr_type=None):
        badger_graph = nx.Graph()
        source_vertex_attr_value_idx = None
        target_vertex_attr_value_idx = None

        if ("urn-cptl-HOST-ipv4" == source_vertex_attr_type and\
                  "urn-cptl-HOST-hostname" == target_vertex_attr_type):
            file = self.pandect_data_dir + "/test/resources" + "/dst.url-uniq"
            source_vertex_attr_value_idx = 0
            target_vertex_attr_value_idx = 1
        elif ("urn-cptl-HOST-ipv4" == source_vertex_attr_type and\
                  "urn-cptl-HOST-ipv4" == target_vertex_attr_type):
            file = self.pandect_data_dir + "/test/resources" + "/dst.ip-uniq"
            source_vertex_attr_value_idx = 0
            target_vertex_attr_value_idx = 1
        elif ("urn-cptl-HOST-ipv4" == source_vertex_attr_type and\
                  "urn-cptl-HOST-tag-tldcount" == target_vertex_attr_type):
            file = self.pandect_data_dir + "/test/resources" + "/dst.url-uniq.tldcount"
            source_vertex_attr_value_idx = 0
            target_vertex_attr_value_idx = 1
        elif ("urn-cptl-HOST-ipv4" == source_vertex_attr_type and\
                  "urn-cptl-HOST-tag-cccount" == target_vertex_attr_type):
            file = self.pandect_data_dir + "/test/resources" + "/dst.cc-uniq.cccount"
            source_vertex_attr_value_idx = 0
            target_vertex_attr_value_idx = 1            
        else:
            raise Exception("Unknown!")

        # We have the selected vertex urn, add a node for that in 
        #  the return graph.  (e.g. HOST_4)
        badger_graph.add_node(0, {source_vertex_attr_type:source_vertex_attr_value})
        i = 1

        f = open(file)
        lines = f.readlines()
        for line in lines:
            line = line.rstrip("\n")
            line_pcs = line.split(":")
            vertex_attr_value = line_pcs[source_vertex_attr_value_idx]
            target_attr_value = line_pcs[target_vertex_attr_value_idx]
            # Add a name for every hostname and an edge from the 
            #  selected_vertex_urn to that hostname
            if vertex_attr_value == source_vertex_attr_value:
                if "urn-cptl-HOST-tag-tldcount" == target_vertex_attr_type or\
                        "urn-cptl-HOST-tag-cccount" == target_vertex_attr_type:
                    target_attr_value += "," + line_pcs[2]
                badger_graph.add_node(i, {target_vertex_attr_type:target_attr_value})    
                badger_graph.add_edge(0, i)

            i = i + 1
        f.close()
        result = json_graph.dumps(badger_graph)
        return result

    @cherrypy.expose
    def get_graph(self, datasource=None, selected_vertex_urns=None):
        output_format = "JSON"

        if (datasource != None and \
                "urn:nmap:NAMESPACE:NETWORKS:NETWORK.HOST" == urllib.unquote(datasource)):
            json_cptl_nmap_graph = self.nmDAO.getCPTLGraph(output_format)
            G = json_graph.loads(json_cptl_nmap_graph)
            self.browser_graph = G
        else:
            # This is where CPTL-Aware Resources come into play
            if (datasource != None and\
                    "urn:badger:get_hostip_dest_hostnames" == urllib.unquote(datasource) and\
                    selected_vertex_urns != None):
                source_vertex_attr_type = "urn-cptl-HOST-ipv4"
                target_vertex_attr_type = "urn-cptl-HOST-hostname"
            elif (datasource != None and\
                    "urn:badger:get_host_dest_ips" == urllib.unquote(datasource) and\
                    selected_vertex_urns != None):
                source_vertex_attr_type = "urn-cptl-HOST-ipv4"
                target_vertex_attr_type = "urn-cptl-HOST-ipv4"
            elif (datasource != None and\
                      "urn:badger:get_host_dest_tldcounts" == urllib.unquote(datasource) and\
                      selected_vertex_urns != None):
                source_vertex_attr_type = "urn-cptl-HOST-ipv4"
                target_vertex_attr_type = "urn-cptl-HOST-tag-tldcount"
            elif (datasource != None and\
                      "urn:badger:get_host_dest_cccounts" == urllib.unquote(datasource) and\
                      selected_vertex_urns != None):
                source_vertex_attr_type = "urn-cptl-HOST-ipv4"
                target_vertex_attr_type = "urn-cptl-HOST-tag-cccount"
            else:
                raise Exception("Unrecognized analysis!")

            # Decode the URNs passed in
            datasource = urllib.unquote(datasource)
            decoded_selected_vertex_urns = []
            encoded_selected_vertex_urns = selected_vertex_urns.split(",")
            for encoded_urn in encoded_selected_vertex_urns:
                decoded_urn = urllib.unquote(encoded_urn)
                decoded_selected_vertex_urns.append(decoded_urn)

            # We need to write code to resolve this IP from the selected vertex urn
            for selected_vertex_urn in decoded_selected_vertex_urns:
                #print "SELECTED urn: " + selected_vertex_urn
                source_vertex_id = None
                source_vertex = None
                source_vertex_attr_value = None

                # Find the node that corresponds to the selected_vertex_urn
                for node in self.browser_graph.nodes(data=True):
                    node_id = node[0]
                    node_dict = node[1]
                    if (node_dict['urn_id'] == selected_vertex_urn):
                        source_vertex_id = node_id
                        source_vertex = node;  # need to fix this
                        source_vertex_dict = node[1]
                        source_vertex_attr_value = source_vertex_dict[source_vertex_attr_type]
                        break

                # Now get the information
                json_badger_graph =\
                    self._badger_get_host_dest_info(source_vertex_attr_value,\
                                                        source_vertex_attr_type,\
                                                        target_vertex_attr_type)            
                G = self.browser_graph
                #self.write_graph(G, "/tmp/G.json")
                H = json_graph.loads(json_badger_graph)
                #self.write_graph(H, "/tmp/H.json")
                self.browser_graph = self.combine_graphs(G,\
                                                             H,\
                                                             source_vertex_attr_type,\
                                                             source_vertex_attr_value,\
                                                             target_vertex_attr_type);
        #updated_graph = nx.compose(current_graph, graph_extensions)
        #self.write_graph(self.browser_graph, "/tmp/C.json")
        json_updated_graph = json_graph.dumps(self.browser_graph)
        return json_updated_graph
    
    def write_graph(self, G, file_path):
        f = open(file_path, 'w')
        jg = json_graph.dumps(G)
        f.write(jg)
        f.close()
        
    def combine_graphs(self, G, H, source_vertex_attr_type,\
                           source_vertex_attr_value,\
                           target_vertex_attr_type):
        # For each edge from node[0] in H, add the edge in G
        
        # Given G and H, identity is given via equality on the source_vertex_attr_type
        #   join on the source_vertex_attr type
        v_G_source_attr_value2id = self.get_vertex_attr_value2id(G, source_vertex_attr_type)
        v_G_target_attr_value2id = self.get_vertex_attr_value2id(G, target_vertex_attr_type)
        v_H_source_attr_value2id = self.get_vertex_attr_value2id(H, source_vertex_attr_type)
        v_H_target_attr_value2id = self.get_vertex_attr_value2id(H, target_vertex_attr_type)
        
        v_H_id2v_G_id = {}

        # 2.  Add all the nodes in H (except for node 0) to the browser graph
        #     a.  If h attr value \in V[H] && h attr value \in G, then merge attributes of h and g into G
        #          update h2g_node_ids[hnode_id] = gnode_id
        #     b.  Otherwise, add h
        new_node_id = nx.number_of_nodes(G) + 1
        V_H = H.nodes(data=True)
        for v_H in V_H:
            v_H_id = v_H[0]
            v_H_dict = v_H[1]
            if source_vertex_attr_type not in v_H_dict.keys() and\
                    target_vertex_attr_type not in v_H_dict.keys():
                # The node doesn't have the source or target attribute type
                #print "NODE ADD: " + str(new_node_id)
                #print v_H_dict
                v_H_id2v_G_id[v_H_id] = new_node_id
                G.add_node(new_node_id, v_H_dict)
                new_node_id = new_node_id + 1
            elif target_vertex_attr_type in v_H_dict.keys() and\
                    v_H_dict[target_vertex_attr_type] != None and \
                    (v_H_dict[target_vertex_attr_type] in v_G_target_attr_value2id.keys() or\
                         v_H_dict[target_vertex_attr_type].split(",")[0] in v_G_target_attr_value2id.keys()):
                
                #print "v_H dict: " 
                #print v_H_dict 
                #print "target_vertex_attr_type:" 
                #print target_vertex_attr_type
                
                # HACK:
                split_target_vertex_attr_types = [ "urn-cptl-HOST-tag-cccount", "urn-cptl-HOST-tag-tldcount" ]
                # The node can be joined via the target attribute type
                #    and it has a matching value
                v_H_target_attr_value = v_H_dict[target_vertex_attr_type]
                if (target_vertex_attr_type in split_target_vertex_attr_types):
                    v_H_target_attr_value = v_H_target_attr_value.split(",")[0]
                    #print "v_H_target_attr_value: " + v_H_target_attr_value
                v_G_id = v_G_target_attr_value2id[ v_H_target_attr_value ]
                #print "Vertex in G with same value: " + str(v_G_id)
                
                # 2a.  Merge the attributes of v_H and v_G into G
                v_G = G.nodes(data=True)[v_G_id - 1]
                v_G_dict = v_G[1]
                #print "Vertex G dictionary: " 
                #print v_G_dict
                #print "Real vertex G id: "
                #print v_G[0]
                for h_key in v_H_dict.keys():
                    # If there is a key in v_H, not in v_H, add it to v_G
                    if not h_key in v_G_dict.keys():
                        v_G_dict[h_key] = v_H_dict[h_key]
                    elif target_vertex_attr_type in split_target_vertex_attr_types:
                        country_g = v_G_dict[h_key].split(",")[0]
                        country_h = v_H_dict[h_key].split(",")[0]
                        if country_h == country_g:
                            value = int(v_H_dict[h_key].split(",")[1]) + int(v_G_dict[h_key].split(",")[1])
                            v_G_dict[h_key] = v_H_dict[h_key].split(",")[0] + "," + str(value)
                            #print "ADDED w ADDITION: " + h_key + ":" + v_G_dict[h_key]
                # 2aii.  Update 
                #print "NODE COLLISION: " + v_H_target_attr_value 
                #print str(v_H_id) + "->" + str(v_G_id)
                v_H_id2v_G_id[v_H_id] = v_G_id;                
            elif source_vertex_attr_type in v_H_dict.keys() and\
                    v_H_dict[source_vertex_attr_type] != None and \
                    v_H_dict[source_vertex_attr_type] in v_G_source_attr_value2id.keys():

                # The node can be joined via the source attribute type
                #    and it has a matching value
                v_H_source_attr_value = v_H_dict[source_vertex_attr_type]
                v_G_id = v_G_source_attr_value2id[ v_H_source_attr_value ]

                # 2a.  Merge the attributes of v_H and v_G into G
                v_G = G.nodes(data=True)[v_G_id - 1]
                v_G_dict = v_G[1]
                for h_key in v_H_dict.keys():
                    # If there is a key in v_H, not in v_H, add it to v_G
                    if not h_key in v_G_dict.keys():
                        v_G_dict[h_key] = v_H_dict[h_key];
                # 2aii.  Update 
                #print "NODE COLLISION: " + v_H_source_attr_value 
                #print str(v_H_id) + "->" + str(v_G_id)
                v_H_id2v_G_id[v_H_id] = v_G_id;
            else:
                # The node has source or target attribute type
                #   but it doesn't have a matching value
                #print "NODE ADD: " + str(new_node_id) 
                #print v_H_dict
                v_H_id2v_G_id[v_H_id] = new_node_id
                G.add_node(new_node_id, v_H_dict)
                new_node_id = new_node_id + 1
                
        # 3.  Add all the edges in H to the browser graph
        #     a.  If e \in H[E] contains a vertex in h2g_node_ids.keys(), then delete the old edge, create a new on in G
        #     b.  Otherwise, add e
        E_H = list(H.edges(data=True))
        for e_H in E_H:
            e_H_source_id = e_H[0]
            e_H_target_id = e_H[1]
            e_H_dict = e_H[2]
            
            new_G_source = v_H_id2v_G_id[e_H_source_id]
            new_G_target = v_H_id2v_G_id[e_H_target_id]
            new_G_dict = e_H_dict
            
            #print "Add edge" + str(new_G_source) + "," + str(new_G_target)
            G.add_edge(new_G_source, new_G_target, new_G_dict);

        return G    
        
    def get_vertex_attr_value2id(self, G, vertex_attr_type):
        nodeid2vav = {}
        for gnode in G.nodes(data=True):
            gnode_id = gnode[0]
            gnode_dict = gnode[1]
            if vertex_attr_type in gnode_dict:
                gnode_vertex_attr_value = gnode_dict[vertex_attr_type]
                if ("urn-cptl-HOST-tag-cccount" == vertex_attr_type or\
                        "urn-cptl-HOST-tag-tldcount" == vertex_attr_type):
                    gnode_vertex_attr_value = gnode_dict[vertex_attr_type].split(",")[0]
                nodeid2vav[gnode_vertex_attr_value] = gnode_id
        return nodeid2vav

    @cherrypy.expose
    def get_adjacent_edge_types(self, vertex_type_urns):
        vertex_type_urns_array = vertex_type_urns.split(",")
        adj_e_list = "<ul id=\"adjacent-edge-types-panel-content-listview\" data-role=\"listview\" data-inset=\"true\" data-filter=\"true\">"
        for vertex_type_urn in vertex_type_urns_array:
            vertex_type_urn = urllib.unquote(vertex_type_urn)
            adj_e_list += "<li class=\"vertex_type\" data-role=\"list-divider\">" +\
                "Relations From cptl:HOST </li>"
            if "cptl:HOST" == vertex_type_urn or "urn:nmap:NAMESPACE:NETWORKS.NETWORK:HOST" == vertex_type_urn:
                adj_e_list += "<li class=\"infosource\" onclick=\"get_infosource('urn:badger:get_host_dest_ips')\">Get Unique Dest IPs</li>"
                adj_e_list += "<li class=\"infosource\" onclick=\"get_infosource('urn:badger:get_hostip_dest_hostnames')\">Get Unique Dest Hostnames</li>"
                adj_e_list += "<li class=\"infosource\" onclick=\"get_infosource('urn:badger:get_host_dest_tldcounts')\">Get Dest TLDs</li>"
                adj_e_list += "<li class=\"infosource\" onclick=\"get_infosource('urn:badger:get_host_dest_cccounts')\">Get Dest Country Codes</li>"
        adj_e_list += "</ul>"
        return adj_e_list

    @cherrypy.expose
    def get_vertices_edges_data(self, vertex_urns, edge_urns):
        vertex_urns_array = vertex_urns.split(",")
        v_e_list = "<ul id=\"selected-vertices-edges-panel-content-listview\" data-role=\"listview\" data-inset=\"true\" data-filter=\"true\">"
        for vertex_urn in vertex_urns_array:
            v_e_list += "<li class=\"vertex\">" + urllib.unquote(vertex_urn) + "</li>"
        v_e_list += "</ul>"
        return v_e_list

    @cherrypy.expose
    def get_stylesheets(self):
        adj_e_list = "<ul id=\"apply-stylesheet-panel-content-listview\" data-role=\"listview\" data-inset=\"true\" data-filter=\"true\">"
        adj_e_list += "<li class=\"infosource\" onclick=\"apply_stylesheet('urn-cptl-HOST-tld')\">Style TLDs</li>"
        adj_e_list += "<li class=\"infosource\" onclick=\"apply_stylesheet('urn-cptl-HOST-cc')\">Style Country Codes</li>"
        adj_e_list += "</ul>"
        return adj_e_list

if __name__ == '__main__':
    conf = {
        '/': {
            'tools.sessions.on':True,
            'tools.staticdir.root': os.path.abspath(os.getcwd())
            },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'src/pandect/public'
            }
        }
    
    webapp = Browser()
    cherrypy.quickstart(webapp, '/', conf)
