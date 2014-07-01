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
import sys

# USAGE:
# python domain.py /path/to/pypandect/data/test/resources/dst.url-uniq > 
#    /path/to/pypandect/data/test/resources/dst.url-uniq.tldcount
file_path = sys.argv[1]
f = open(file_path)
lines = f.readlines()

source_tld_counts = {}
for line in lines:
    line = line.rstrip("\n")
    line_pcs = line.split(":")
    source_ip = line_pcs[0]
    domain = line_pcs[1]

    # Get the map going
    if ( not source_ip in source_tld_counts.keys() ):
        source_tld_counts[source_ip] = {}
    source_ip_tlds = source_tld_counts[source_ip].keys()

    # Process the domain
    domain_pcs = domain.split(".")
    num_pcs = len(domain_pcs)
    tld_idx = num_pcs - 1
    tld = domain_pcs[num_pcs - 1]

    if not tld in source_ip_tlds:
        source_tld_counts[source_ip][tld] = 1
    else:
        source_tld_counts[source_ip][tld] += 1

output = []
for source in source_tld_counts.keys():
    for tld in source_tld_counts[source].keys():
        count = source_tld_counts[source][tld]
        output.append(source + ":" + tld + ":" + str(count))

print "\n".join(output)

f.close()
