function visualize_graph(svg_graph_id, svg, data, vis_type, width, height) {
    if ("FORCE_DIRECTED_FISHEYE" == vis_type) {
	visualize_graph_force_directed_fisheye(svg_graph_id, svg, data, width, height);
    } else {
	alert("Visualization type (" + vis_type + ") undefined!");
    }
}

function visualize_graph_force_directed_fisheye(svg_graph_id, svg, data, width, height) {

    var color = d3.scale.category20();
    
    var fisheye = d3.fisheye.circular()
      .radius(120);

    var force = d3.layout.force()
	.charge(-900)
	.linkDistance(100)
	.size([width, height]);
    
    var n = data.nodes.length;
    
    force.nodes(data.nodes).links(data.links);
    
    // Initialize the positions deterministically, for better results.
    data.nodes.forEach(function(d, i) { d.x = d.y = width / n * i; });
    
    // Run the layout a fixed number of times.
    // The ideal number of times scales with graph complexity
    // Of course, don't run too long--you'll hang the page!
    force.start();
    for (var i = n; i > 0; --i) {
	force.tick();
    }
    force.stop();

    // Center the nodes in the middle.
    var ox = 0, oy = 0;
    data.nodes.forEach(function(d) { ox += d.x, oy += d.y; });
    ox = ox / n - width / 2, oy = oy / n - height / 2;
    data.nodes.forEach(function(d) { d.x -= ox, d.y -= oy; });

    var link = svg.selectAll(".link")
	.data(data.links)
	.enter().append("line")
	.attr("class", "link")
	.attr("x1", function(d) { return d.source.x; })
	.attr("y1", function(d) { return d.source.y; })
	.attr("x2", function(d) { return d.target.x; })
	.attr("y2", function(d) { return d.target.y; })
	.style("stroke-width", function(d) { return Math.sqrt(d.value); })
	.style("stroke", "white");
    
    var node = svg.selectAll(".node")
	.data(data.nodes)
	.enter().append("g")
	.attr("class","node")
	.call(force.drag);

    node.append("circle")
	.attr("cx", function(d) {return d.x;})
	.attr("cy", function(d) {return d.y;})
	.attr("r", 4.5)
	.style("fill", function(d) {return color(d.group);});

    node.append("text")
	.attr("dx", function(d) { return d.x; } )
	.attr("dy", function(d) { return d.y; } )
	.style("fill", "white")
	.text(function(d) {return d.id});
	
    svg.on("mousemove", function() {
	    fisheye.focus(d3.mouse(this));
	    
	    node.select("circle").each(function(d) { d.fisheye = fisheye(d); })
		.attr("cx", function(d) { return d.fisheye.x; })
		.attr("cy", function(d) { return d.fisheye.y; })
		.attr("r", function(d) { if (d.r != null) {
			                   return d.fisheye.z * d.r; 
			                 } else { 
                			    return d.fisheye.z * 4.5;
			}});

	    node.select("text").each(function(d) { d.fisheye = fisheye(d); })
		.attr("dx", function(d) { return d.fisheye.x; })
		.attr("dy", function(d) { return d.fisheye.y; });
	    
	    link.attr("x1", function(d) { return d.source.fisheye.x; })
		.attr("y1", function(d) { return d.source.fisheye.y; })
		.attr("x2", function(d) { return d.target.fisheye.x; })
		.attr("y2", function(d) { return d.target.fisheye.y; })
		});
    
}

