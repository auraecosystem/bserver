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
