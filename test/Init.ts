import { parseYamlToAST, compileASTToHTML, ParserError } from "../src/parser";
import * as fs from "fs";
import * as path from "path";

describe("AST Parser Spec Compliance", () => {
  describe("Phase 1: Lexical Disambiguation & Key Parsing", () => {
    it("should classify top-level prefixes correctly (^, +, $, main)", () => {
      const fixturePath = path.join(__dirname, "fixtures/01-prefixes.yml");
      const expectedPath = path.join(__dirname, "fixtures/01-prefixes.ast.json");

      const source = fs.readFileSync(fixturePath, "utf-8");
      const expectedAST = JSON.parse(fs.readFileSync(expectedPath, "utf-8"));

      const ast = parseYamlToAST(source);
      expect(ast).toEqual(expectedAST);
    });

    it("should throw a ParserError if 'main' key is missing", () => {
      const invalidYaml = `
^card:
  tag: div
`;
      expect(() => parseYamlToAST(invalidYaml)).toThrow(ParserError);
      expect(() => parseYamlToAST(invalidYaml)).toThrow(/Missing required root key 'main'/);
    });
  });

  describe("Phase 2: Dynamic Reference Extraction", () => {
    it("should distinguish Static parameters from Dynamic References ($)", () => {
      const fixturePath = path.join(__dirname, "fixtures/02-dynamic-refs.yml");
      const expectedPath = path.join(__dirname, "fixtures/02-dynamic-refs.ast.json");

      const source = fs.readFileSync(fixturePath, "utf-8");
      const expectedAST = JSON.parse(fs.readFileSync(expectedPath, "utf-8"));

      const ast = parseYamlToAST(source);
      expect(ast).toEqual(expectedAST);
    });

    it("should parse scalar reference without path ($sourceName)", () => {
      const source = `
main:
  - button:
      params:
        label: $buttonLabel
`;
      const ast = parseYamlToAST(source);
      const component = ast.root[0] as any;

      expect(component.params.label).toEqual({
        kind: "DynamicReference",
        sourceName: "buttonLabel",
        path: undefined,
      });
    });
  });

  describe("Phase 3 & 4: Schema Merging & HTML Compilation", () => {
    it("should merge '+' extension params into '^' format defaults", () => {
      const source = `
^btn:
  tag: button
  params: { color: blue, size: small }
  template: '<button class="btn btn-\${color} btn-\${size}">\${children}</button>'

+btn:
  params: { size: large }

main:
  - btn:
      children: "Click"
`;
      const ast = parseYamlToAST(source);
      const html = compileASTToHTML(ast);

      expect(html).toBe('<button class="btn btn-blue btn-large">Click</button>');
    });

    it("should resolve dynamic script symbols during compilation", () => {
      const source = `
$config:
  script: javascript
  code: |
    print(JSON.stringify({ title: "Dynamic Title" }));

^header:
  template: '<h1>\${title}</h1>'

main:
  - header:
      params:
        title: $config.title
`;
      const ast = parseYamlToAST(source);
      const html = compileASTToHTML(ast);

      expect(html).toBe("<h1>Dynamic Title</h1>");
    });

    it("should throw an unhandled reference error if data source is missing", () => {
      const source = `
main:
  - header:
      params:
        title: $missingSource.title
`;
      const ast = parseYamlToAST(source);
      expect(() => compileASTToHTML(ast)).toThrow(/Unresolved data source: missingSource/);
    });
  });
});
