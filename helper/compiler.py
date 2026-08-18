def evaluate_node(node, symbol_table, formats):
    if node.type == "TextNode":
        return escape_html(node.value)
    
    # 1. Look up Format Definition
    fmt = formats.get(node.name, default_format(node.name))
    
    # 2. Resolve Instance Parameters against Symbol Table
    resolved_params = deep_copy(fmt.params)
    for key, val_node in node.params.items():
        resolved_params[key] = resolve_value(val_node, symbol_table)
        
    # 3. Evaluate Children Recursively
    children_html = "".join([evaluate_node(child, symbol_table, formats) for child in node.children])
    
    # 4. Render Template or Default Tag
    if fmt.template:
        context = { **resolved_params, "children": children_html }
        return interpolate_template(fmt.template, context)
    else:
        return render_default_tag(fmt.tag or node.name, resolved_params, children_html)
