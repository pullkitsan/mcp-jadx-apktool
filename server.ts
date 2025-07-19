#!/usr/bin/env ts-node
import { Server } from "./sdk/src/server/index.js";
import { StdioServerTransport } from "./sdk/src/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  InitializeRequestSchema,
  type ServerResult
} from "./sdk/src/types.js";
import dotenv from "dotenv";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import fs from "fs";
import path from "path";
import os from "os";
import { exec } from "child_process";
import { parseStringPromise } from "xml2js";

dotenv.config({ path: path.resolve(__dirname, ".env") });

const TMP_LOG = path.join(os.tmpdir(), "mcp-reverse.log");

function log(msg: string): void {
  const entry = `[${new Date().toISOString()}] ${msg}\n`;
  fs.appendFileSync(TMP_LOG, entry);
  console.error(entry.trim());
}

const ReverseAPKArgsSchema = z.object({
  file: z.string().describe("Path to the APK file to reverse engineer")
});

const SearchArgsSchema = z.object({
  queryStrings: z.array(z.string()).nonempty().describe("List of strings to search for"),
  directory: z.string().optional().describe("Directory to search in (defaults to last reversed output)")
});

const ReadFileArgsSchema = z.object({
  filePath: z.string().describe("Relative path of the file to read from reversed output")
});

type ReverseArgs = z.infer<typeof ReverseAPKArgsSchema>;
type SearchArgs = z.infer<typeof SearchArgsSchema>;
type ReadFileArgs = z.infer<typeof ReadFileArgsSchema>;

let LAST_REVERSE_DIR: string | null = null;

async function reverseAPK({ file }: ReverseArgs): Promise<ServerResult> {
  const baseName = path.basename(file, ".apk");
  const outputBaseDir = path.join(os.tmpdir(), baseName);
  const jadxDir = path.join(outputBaseDir, "jadx");
  const apktoolDir = path.join(outputBaseDir, "apktool");

  fs.mkdirSync(jadxDir, { recursive: true });
  fs.mkdirSync(apktoolDir, { recursive: true });

  LAST_REVERSE_DIR = outputBaseDir;

  return new Promise((resolve) => {
    exec(`jadx -d "${jadxDir}" "${file}"`, (jadxErr: any, stdout1: any, stderr1: any) => {
      if (jadxErr) {
        log(`⚠️ Jadx exited with non-zero code (continuing): ${jadxErr.message}`);
        log(`stderr: ${stderr1}`);
        log(`stdout: ${stdout1}`);
      }

      exec(`apktool d -f -o "${apktoolDir}" "${file}"`, async (apktoolErr: any, stdout2: any, stderr2: any) => {
        if (apktoolErr) {
          log(`❌ APKTool failed: ${stderr2}`);
          return resolve({
            isError: true,
            content: [{ type: "text", text: `APKTool failed: ${stderr2}\n` }]
          });
        }

        const manifestPath = path.join(apktoolDir, "AndroidManifest.xml");
        let manifestSummary = "";

        try {
          const manifestContent = fs.readFileSync(manifestPath, "utf-8");

          const packageNameMatch = manifestContent.match(/package=\"([^\"]+)\"/);
          const versionNameMatch = manifestContent.match(/android:versionName=\"([^\"]+)\"/);
          const versionCodeMatch = manifestContent.match(/android:versionCode=\"([^\"]+)\"/);

          const packageName = packageNameMatch ? packageNameMatch[1] : "Unknown";
          const versionName = versionNameMatch ? versionNameMatch[1] : "Unknown";
          const versionCode = versionCodeMatch ? versionCodeMatch[1] : "Unknown";

          manifestSummary = `\n📄 **Manifest Summary**\n- **Package:** ${packageName}\n- **Version Name:** ${versionName}\n- **Version Code:** ${versionCode}`;

        } catch (parseErr) {
          log(`⚠️ Failed to parse manifest: ${parseErr}`);
          manifestSummary = "⚠️ Failed to parse AndroidManifest.xml.";
        }

        resolve({
          content: [{
            type: "text",
            text: `✅ Reverse engineering completed.\n\nOutput folders:\n- Jadx: ${jadxDir}\n- APKTool: ${apktoolDir}${manifestSummary}`
          }]
        });
      });
    });
  });
}

async function searchInReversedCode({ queryStrings, directory }: SearchArgs, extra: any): Promise<ServerResult> {
  const searchDir = directory ?? LAST_REVERSE_DIR;
  if (!searchDir || !fs.existsSync(searchDir) || !fs.statSync(searchDir).isDirectory()) {
    return {
      isError: true,
      content: [{ type: "text", text: "Provided path is not a valid directory. Run reverseAPK first or specify a directory." }]
    };
  }

  let streamedCount = 0;
  const results: string[] = [];

  function flushChunk() {
    if (results.length > 0 && extra?.sendProgress) {
      extra.sendProgress({
        content: [{ type: "text", text: results.join("\n\n") }],
        append: true
      });
      results.length = 0;
    }
  }

  function walk(dir: string) {
    for (const file of fs.readdirSync(dir)) {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        walk(fullPath);
      } else if (/\.(java|smali|xml|txt)$/.test(file)) {
        const content = fs.readFileSync(fullPath, "utf-8");
        const lines = content.split(/\r?\n/);
        const relPath = path.relative(searchDir!, fullPath);

        lines.forEach((line, i) => {
          queryStrings.forEach((q) => {
            if (line.includes(q)) {
              streamedCount++;
              results.push(
                `📄 File: \`${relPath}\`\n🔍 Line ${i + 1}: ${line.trim()}\n🧾 Use this path with \`readFileFromReversedCode\`: \`${relPath}\``
              );
              if (results.length >= 5) flushChunk();
            }
          });
        });
      }
    }
  }

  walk(searchDir);
  flushChunk();

  return {
    content: [{
      type: "text",
      text: streamedCount
        ? `✅ Done. Found and streamed ${streamedCount} matching line(s).`
        : "❌ No matches found for the provided strings."
    }]
  };
}

async function readFileFromReversedCode({ filePath }: ReadFileArgs): Promise<ServerResult> {
  if (!LAST_REVERSE_DIR) {
    return {
      isError: true,
      content: [{ type: "text", text: "❌ No reversed directory found. Please run reverseAPK first." }]
    };
  }

  const fullPath = path.join(LAST_REVERSE_DIR, filePath);

  if (!fs.existsSync(fullPath)) {
    return {
      isError: true,
      content: [{ type: "text", text: `❌ File not found: ${filePath}` }]
    };
  }

  const content = fs.readFileSync(fullPath, "utf-8");
  return {
    content: [{ type: "text", text: `📄 ${filePath}\n\n${content}` }]
  };
}

const server = new Server(
  { name: "reverse-apk", version: "1.0.0" },
  { capabilities: { tools: { listChanged: true } } }
);

server.setRequestHandler(InitializeRequestSchema, async () => ({
  protocolVersion: "2024-11-05",
  capabilities: { tools: { listChanged: true } },
  serverInfo: { name: "reverse-apk", version: "1.0.0" },
  instructions: "This tool reverse engineers APKs using Jadx and Apktool, and allows searching for strings or reading files in the output."
}));

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "reverseAPK", description: "Reverse engineer an APK using Jadx and APKTool", inputSchema: zodToJsonSchema(ReverseAPKArgsSchema) },
    { name: "searchInReversedCode", description: "Search for specific strings in the reversed APK output", inputSchema: zodToJsonSchema(SearchArgsSchema) },
    { name: "readFileFromReversedCode", description: "Read a file from the reversed APK output by relative path", inputSchema: zodToJsonSchema(ReadFileArgsSchema) }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
  const { name, arguments: args } = req.params;

  if (name === "reverseAPK") {
    const parsed = ReverseAPKArgsSchema.safeParse(args);
    return parsed.success ? reverseAPK(parsed.data) : { isError: true, content: [{ type: "text", text: "Invalid input to reverseAPK" }] };
  }

  if (name === "searchInReversedCode") {
    const parsed = SearchArgsSchema.safeParse(args);
    return parsed.success ? searchInReversedCode(parsed.data, extra) : { isError: true, content: [{ type: "text", text: "Invalid input to searchInReversedCode" }] };
  }

  if (name === "readFileFromReversedCode") {
    const parsed = ReadFileArgsSchema.safeParse(args);
    return parsed.success ? readFileFromReversedCode(parsed.data) : { isError: true, content: [{ type: "text", text: "Invalid input to readFileFromReversedCode" }] };
  }

  return { isError: true, content: [{ type: "text", text: `Unknown tool: ${name}` }] };
});

async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

run();
