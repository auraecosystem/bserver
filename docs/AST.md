## 1. Abstract Syntax Tree (AST) Definition

The following TypeScript interfaces define the AST emitted by the parser prior to execution and code generation.

```typescript
// Document Root
export interface DocumentAST {
  type: "Document";
  formats: Map<string, FormatDefinitionNode>;
  extensions: ExtensionNode[];
  dataSources: Map<string, DataSourceNode>;
  root: ContentNode[];
}

// Prefix: ^ (Format Definition)
export interface FormatDefinitionNode {
  type: "FormatDefinition";
  name: string;
  tag?: string;
  params: Record<string, any>;
  template?: string;
}

// Prefix: + (Extension / Merge)
export interface ExtensionNode {
  type: "Extension";
  target: string;
  payload: Record<string, any> | Array<any>;
}

// Prefix: $ (Data Source Script)
export interface DataSourceNode {
  type: "DataSource";
  name: string;
  language: string;
  code: string;
}

// Prefix: None (Content / Component Node)
export interface ComponentNode {
  type: "ComponentInstance";
  name: string;
  params: Record<string, ValueNode>;
  children: ContentNode[];
}

export interface TextNode {
  type: "TextNode";
  value: string;
}

export type ContentNode = ComponentNode | TextNode;

// Value Nodes (Props/Parameters)
export type ValueNode = StaticValueNode | DynamicReferenceNode;

export interface StaticValueNode {
  kind: "Static";
  value: any;
}

export interface DynamicReferenceNode {
  kind: "DynamicReference";
  sourceName: string; // e.g., "userProfile"
  path?: string;       // e.g., "role"
}

```

---

## 2. Lexical Disambiguation & Parsing Rules

The parser ingests a validated YAML Object Model and transforms it into the `DocumentAST` using key-prefix pattern matching.

### 2.1 Root Key Classification Grammar

Let $K$ be a string representing a top-level YAML dictionary key:

$$\text{NodeType}(K) =  \begin{cases}  \text{FormatDefinition} & \text{if } K \text{ matches } \mathtt{\hat{}}[a\text{-}zA\text{-}Z0\text{-}9\text{\_}\text{-}]+ \\ \text{Extension} & \text{if } K \text{ matches } \mathtt{+}[a\text{-}zA\text{-}Z0\text{-}9\text{\_}\text{-}]+ \\ \text{DataSource} & \text{if } K \text{ matches } \mathtt{\$}[a\text{-}zA\text{-}Z0\text{-}9\text{\_}\text{-}]+ \\ \text{RootContent} & \text{if } K = \text{"main"} \\ \text{MetaData} & \text{otherwise} \end{cases}$$

### 2.2 Dynamic Reference Parsing

When parsing scalar or map values within `params`:

* If a string matches the expression `^\$([a-zA-Z0-9_-]+)(\.([a-zA-Z0-9_.-]+))?$`:
* Extract `sourceName` = Group 1
* Extract `path` = Group 3
* Emit `DynamicReferenceNode`


* Otherwise, emit `StaticValueNode`.

---

## 3. Compilation Pipeline Specification

The compiler operates in four sequential phases:

```
[YAML Source] ──► Phase 1: AST Construction ──► Phase 2: Data Execution 
                                                       │
[HTML Output] ◄── Phase 4: HTML Generation  ◄── Phase 3: Schema Merging

```

### Phase 1: AST Construction

1. Parse raw YAML source into standard Object AST.
2. Iterate through root keys, apply classification regexes, and construct `DocumentAST`.
3. Recursively descend into `main:` block to map plain keys into nested `ComponentNode` trees.

### Phase 2: Data Source Execution (`$`)

1. Instantiates a isolated execution environment for each `DataSourceNode`.
2. Executes script code (`javascript`, etc.) and captures standard output or return payload.
3. Decodes payload string as JSON and populates runtime `SymbolTable`:

$$\text{SymbolTable}[{\text{node.name}}] \leftarrow \text{JSON.parse}(\text{result})$$



### Phase 3: Extension & Schema Merging (`+`)

For each `ExtensionNode` in `DocumentAST.extensions`:

1. **Format Override**: If `ExtensionNode.target` matches a key in `DocumentAST.formats`:

$$\text{Format.params} \leftarrow \text{DeepMerge}(\text{Format.params}, \text{Extension.payload.params})$$


2. **Global Context Injection**: If `ExtensionNode.target` maps to system head bindings (e.g., `headlink`):

$$\text{GlobalContext}[\text{target}] \leftarrow \text{Concat}(\text{GlobalContext}[\text{target}], \text{Extension.payload})$$



### Phase 4: Tree Evaluation & HTML Emission

The compiler recursively resolves each `ComponentNode` using standard evaluation logic:

```python
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

```

---

## 4. Parameter Interpolation & Formatting Rules

1. **Template Placeholder Syntax**: `${identifier}` or `${expression}` within `FormatDefinitionNode.template`.
2. **Boolean Attributes**: Properties resolving to `false` or `null` within HTML tag attributes are omitted entirely during rendering (e.g., `disabled="${disabled}"` renders empty string if `disabled: false`).
3. **Implicit HTML Escaping**: All `StaticValueNode` and resolved `DynamicReferenceNode` values rendered into generic textual bodies must be HTML-entity escaped unless explicitly defined as raw markup via a custom unsafe directive.

---
