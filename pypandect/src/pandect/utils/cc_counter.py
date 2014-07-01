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
# python domain.py /path/to/pypandect/data/test/resources/dst.cc-uniq > 
#    /path/to/pypandect/data/test/resources/dst.cc-uniq.cccount
file_path = sys.argv[1]
f = open(file_path)
lines = f.readlines()

source_country_counts = {}
for line in lines:
    line = line.rstrip("\n")
    line_pcs = line.split(":")
    source_ip = line_pcs[0]
    country = line_pcs[2]

    if ( not source_ip in source_country_counts.keys() ):
        source_country_counts[source_ip] = {}

    source_ip_countries = source_country_counts[source_ip].keys()

    if not country in source_ip_countries:
        source_country_counts[source_ip][country] = 1
    else:
        source_country_counts[source_ip][country] += 1

output = []
for source in source_country_counts.keys():
    for country in source_country_counts[source].keys():
        count = source_country_counts[source][country]
        output.append(source + ":" + country + ":" + str(count))

print "\n".join(output)

f.close()

