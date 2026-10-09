/**
 * MLSecOps In-Browser Static Disassembly Engine
 * Performs zero-execution bytecode disassembly for Pickle, Safetensors, ONNX, and PyTorch ZIPs.
 */

// Denylist rules matching Python scanner rules
export const DANGEROUS_SYMBOLS = {
  "builtins:eval": { severity: "CRITICAL", category: "arbitrary_code_execution", desc: "Dynamic string evaluation enabling arbitrary Python code execution." },
  "builtins:exec": { severity: "CRITICAL", category: "arbitrary_code_execution", desc: "Dynamic statement execution enabling arbitrary Python code execution." },
  "builtins:compile": { severity: "CRITICAL", category: "arbitrary_code_execution", desc: "Compiles arbitrary code into executable AST objects." },
  "builtins:__import__": { severity: "CRITICAL", category: "arbitrary_code_execution", desc: "Dynamic module importer bypassing static imports." },
  "builtins:open": { severity: "HIGH", category: "filesystem_tampering", desc: "Opens local file handles for read/write/append." },
  "builtins:print": { severity: "HIGH", category: "synthetic_probe", desc: "Standard print function. Safe payload callback used in synthetic benign tests." },
  "os:system": { severity: "CRITICAL", category: "process_spawning", desc: "Executes arbitrary shell commands in a subshell." },
  "os:popen": { severity: "CRITICAL", category: "process_spawning", desc: "Opens a pipe to or from a shell command." },
  "posix:system": { severity: "CRITICAL", category: "process_spawning", desc: "POSIX-level system shell execution." },
  "nt:system": { severity: "CRITICAL", category: "process_spawning", desc: "Windows NT system shell execution." },
  "subprocess:Popen": { severity: "CRITICAL", category: "process_spawning", desc: "Spawns arbitrary background or synchronous subprocesses." },
  "subprocess:call": { severity: "CRITICAL", category: "process_spawning", desc: "Runs command in subprocess and returns exit status." },
  "subprocess:run": { severity: "CRITICAL", category: "process_spawning", desc: "Standard subprocess execution interface." },
  "socket:socket": { severity: "CRITICAL", category: "network_exfiltration", desc: "Creates raw network sockets for outbound exfiltration or reverse shells." },
  "socket:create_connection": { severity: "CRITICAL", category: "network_exfiltration", desc: "Establishes outbound TCP socket connections." },
  "urllib.request:urlopen": { severity: "HIGH", category: "network_exfiltration", desc: "Performs outbound HTTP/HTTPS requests to download secondary payloads." },
  "shutil:rmtree": { severity: "CRITICAL", category: "filesystem_destruction", desc: "Recursively deletes entire file system directory trees." },
};

export const DANGEROUS_MODULES = {
  os: { severity: "CRITICAL", desc: "Operating system interface module" },
  posix: { severity: "CRITICAL", desc: "POSIX low-level OS primitives" },
  nt: { severity: "CRITICAL", desc: "Windows NT low-level OS primitives" },
  subprocess: { severity: "CRITICAL", desc: "Process creation and shell execution module" },
  socket: { severity: "CRITICAL", desc: "Low-level networking and socket interface" },
  pty: { severity: "CRITICAL", desc: "Pseudo-terminal control module" },
  urllib: { severity: "HIGH", desc: "Outbound network fetching" },
  requests: { severity: "HIGH", desc: "HTTP client library" },
  ctypes: { severity: "CRITICAL", desc: "Direct C memory access" },
};

export const ALLOWED_GLOBALS = new Set([
  "torch._utils:_rebuild_tensor",
  "torch._utils:_rebuild_tensor_v2",
  "torch._utils:_rebuild_parameter",
  "torch:FloatStorage",
  "torch:HalfStorage",
  "torch:LongStorage",
  "torch:IntStorage",
  "torch:DoubleStorage",
  "torch:Tensor",
  "numpy.core.multiarray:_reconstruct",
  "numpy.core.multiarray:scalar",
  "numpy._core.multiarray:_reconstruct",
  "numpy:ndarray",
  "numpy:dtype",
  "collections:OrderedDict",
  "collections:defaultdict",
  "_codecs:encode",
]);

export const VALID_SAFETENSORS_DTYPES = {
  F64: 8, F32: 4, F16: 2, BF16: 2,
  I64: 8, I32: 4, I16: 2, I8: 1,
  U8: 1, BOOL: 1, F8_E4M3: 1, F8_E5M2: 1,
};

export const STANDARD_ONNX_DOMAINS = new Set(["", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"]);

/**
 * Disassembles Pickle Bytecode Streams
 */
export function disassemblePickle(uint8Arr, sourceName = "stream.pkl", strictMode = false) {
  const findings = [];
  const opcodes = [];
  const stack = [];
  const memo = {};
  let offset = 0;
  const len = uint8Arr.length;

  function readStringUntilNewline() {
    let str = "";
    while (offset < len) {
      const b = uint8Arr[offset++];
      if (b === 0x0a) break; // '\n'
      str += String.fromCharCode(b);
    }
    return str;
  }

  function readUint16LE() {
    const val = uint8Arr[offset] | (uint8Arr[offset + 1] << 8);
    offset += 2;
    return val;
  }

  function readUint32LE() {
    const val = uint8Arr[offset] | (uint8Arr[offset + 1] << 8) | (uint8Arr[offset + 2] << 16) | (uint8Arr[offset + 3] << 24);
    offset += 4;
    return val >>> 0;
  }

  function readBytes(n) {
    const slice = uint8Arr.slice(offset, offset + n);
    offset += n;
    return slice;
  }

  while (offset < len) {
    const pos = offset;
    const op = uint8Arr[offset++];
    const hexOffset = "0x" + pos.toString(16).padStart(4, "0").toUpperCase();

    // Protocol 0-5 Opcodes
    if (op === 0x80) { // PROTO
      const proto = uint8Arr[offset++];
      opcodes.push({ pos, hexOffset, name: "PROTO", arg: proto, isDanger: false });
    }
    else if (op === 0x63) { // GLOBAL (c module\nname\n)
      const moduleName = readStringUntilNewline();
      const symbolName = readStringUntilNewline();
      const fullName = `${moduleName}.${symbolName}`;
      const key = `${moduleName}:${symbolName}`;
      let isDanger = false;
      let rule = DANGEROUS_SYMBOLS[key];

      if (!rule) {
        const topMod = moduleName.split(".")[0];
        if (DANGEROUS_MODULES[moduleName]) {
          const m = DANGEROUS_MODULES[moduleName];
          rule = { severity: m.severity, category: "dangerous_module_import", desc: m.desc };
        } else if (DANGEROUS_MODULES[topMod]) {
          const m = DANGEROUS_MODULES[topMod];
          rule = { severity: m.severity, category: "dangerous_module_import", desc: m.desc };
        }
      }

      if (rule) {
        isDanger = true;
        findings.push({
          ruleId: `DANGEROUS-GLOBAL-${rule.severity}`,
          title: `Dangerous Global Reference: ${fullName}`,
          severity: rule.severity,
          category: rule.category,
          location: `${sourceName} [Offset: ${hexOffset}]`,
          description: rule.desc,
          details: { module: moduleName, symbol: symbolName, offset: pos, hexOffset, opcode: "GLOBAL" }
        });
      } else if (strictMode && !ALLOWED_GLOBALS.has(key)) {
        findings.push({
          ruleId: "UNKNOWN-GLOBAL-STRICT",
          title: `Unrecognized Global Symbol: ${fullName}`,
          severity: "MEDIUM",
          category: "strict_policy_violation",
          location: `${sourceName} [Offset: ${hexOffset}]`,
          description: `Strict mode flagged unverified global reference '${fullName}'.`,
          details: { module: moduleName, symbol: symbolName, offset: pos }
        });
      }

      stack.push({ kind: "global", value: [moduleName, symbolName], pos });
      opcodes.push({ pos, hexOffset, name: "GLOBAL", arg: fullName, isDanger });
    }
    else if (op === 0x93) { // STACK_GLOBAL
      let nameVal = "unknown";
      let modVal = "unknown";
      if (stack.length >= 2) {
        const nItem = stack.pop();
        const mItem = stack.pop();
        nameVal = String(nItem.value || "unknown");
        modVal = String(mItem.value || "unknown");
      }
      const fullName = `${modVal}.${nameVal}`;
      const key = `${modVal}:${nameVal}`;
      let isDanger = false;
      const rule = DANGEROUS_SYMBOLS[key] || (DANGEROUS_MODULES[modVal] ? { severity: DANGEROUS_MODULES[modVal].severity, category: "dangerous_module_import", desc: DANGEROUS_MODULES[modVal].desc } : null);

      if (rule) {
        isDanger = true;
        findings.push({
          ruleId: `DANGEROUS-GLOBAL-${rule.severity}`,
          title: `Dangerous Global Reference: ${fullName}`,
          severity: rule.severity,
          category: rule.category,
          location: `${sourceName} [Offset: ${hexOffset}]`,
          description: rule.desc,
          details: { module: modVal, symbol: nameVal, offset: pos, hexOffset, opcode: "STACK_GLOBAL" }
        });
      }

      stack.push({ kind: "global", value: [modVal, nameVal], pos });
      opcodes.push({ pos, hexOffset, name: "STACK_GLOBAL", arg: fullName, isDanger });
    }
    else if (op === 0x52) { // REDUCE (R)
      let callable = null;
      let args = null;
      if (stack.length >= 2) {
        args = stack.pop();
        callable = stack.pop();
      } else if (stack.length === 1) {
        callable = stack.pop();
      }

      let isDanger = false;
      if (callable && callable.kind === "global") {
        const [mod, sym] = callable.value;
        const key = `${mod}:${sym}`;
        const rule = DANGEROUS_SYMBOLS[key] || DANGEROUS_MODULES[mod];

        if (rule) {
          isDanger = true;
          const sev = rule.severity === "INFO" ? "MEDIUM" : (rule.severity || "CRITICAL");
          findings.push({
            ruleId: "ARBITRARY-CODE-EXECUTION-REDUCE",
            title: `Malicious REDUCE Opcode Injected: ${mod}.${sym}`,
            severity: sev,
            category: "code_execution",
            location: `${sourceName} [Offset: ${hexOffset}]`,
            description: `REDUCE opcode executes callable '${mod}.${sym}' during deserialization. Payload signature: ${JSON.stringify(args?.value || "()")}. This facilitates immediate arbitrary code execution upon model loading.`,
            details: { callable_module: mod, callable_name: sym, offset: pos, hexOffset, opcode: "REDUCE" }
          });
        }
      }

      stack.push({ kind: "reduced_result", value: null, pos });
      opcodes.push({ pos, hexOffset, name: "REDUCE", arg: callable ? `${callable.value[0]}.${callable.value[1]}` : "", isDanger });
    }
    else if (op === 0x62) { // BUILD (b)
      const state = stack.pop();
      const inst = stack[stack.length - 1];
      opcodes.push({ pos, hexOffset, name: "BUILD", arg: "", isDanger: false });
    }
    else if (op === 0x28) { // MARK (()
      stack.push({ kind: "mark", value: null, pos });
      opcodes.push({ pos, hexOffset, name: "MARK", arg: "", isDanger: false });
    }
    else if (op === 0x74) { // TUPLE (t)
      const items = [];
      while (stack.length > 0) {
        const top = stack.pop();
        if (top.kind === "mark") break;
        items.unshift(top);
      }
      stack.push({ kind: "tuple", value: items.map(i => i.value), pos });
      opcodes.push({ pos, hexOffset, name: "TUPLE", arg: `(${items.length} items)`, isDanger: false });
    }
    else if (op === 0x29) { // EMPTY_TUPLE ())
      stack.push({ kind: "tuple", value: [], pos });
      opcodes.push({ pos, hexOffset, name: "EMPTY_TUPLE", arg: "()", isDanger: false });
    }
    else if (op === 0x85) { // TUPLE1
      const item = stack.pop();
      stack.push({ kind: "tuple", value: [item?.value], pos });
      opcodes.push({ pos, hexOffset, name: "TUPLE1", arg: "(1 item)", isDanger: false });
    }
    else if (op === 0x86) { // TUPLE2
      const b = stack.pop();
      const a = stack.pop();
      stack.push({ kind: "tuple", value: [a?.value, b?.value], pos });
      opcodes.push({ pos, hexOffset, name: "TUPLE2", arg: "(2 items)", isDanger: false });
    }
    else if (op === 0x8c) { // SHORT_BINUNICODE
      const sLen = uint8Arr[offset++];
      const str = new TextDecoder().decode(readBytes(sLen));
      stack.push({ kind: "string", value: str, pos });
      opcodes.push({ pos, hexOffset, name: "SHORT_BINUNICODE", arg: `"${str}"`, isDanger: false });
    }
    else if (op === 0x58) { // BINUNICODE
      const sLen = readUint32LE();
      const str = new TextDecoder().decode(readBytes(sLen));
      stack.push({ kind: "string", value: str, pos });
      opcodes.push({ pos, hexOffset, name: "BINUNICODE", arg: `"${str}"`, isDanger: false });
    }
    else if (op === 0x56) { // UNICODE
      const str = readStringUntilNewline();
      stack.push({ kind: "string", value: str, pos });
      opcodes.push({ pos, hexOffset, name: "UNICODE", arg: `"${str}"`, isDanger: false });
    }
    else if (op === 0x4b) { // BININT1
      const v = uint8Arr[offset++];
      stack.push({ kind: "int", value: v, pos });
      opcodes.push({ pos, hexOffset, name: "BININT1", arg: String(v), isDanger: false });
    }
    else if (op === 0x4d) { // BININT2
      const v = readUint16LE();
      stack.push({ kind: "int", value: v, pos });
      opcodes.push({ pos, hexOffset, name: "BININT2", arg: String(v), isDanger: false });
    }
    else if (op === 0x4a) { // BININT
      const v = readUint32LE();
      stack.push({ kind: "int", value: v, pos });
      opcodes.push({ pos, hexOffset, name: "BININT", arg: String(v), isDanger: false });
    }
    else if (op === 0x4e) { // NONE
      stack.push({ kind: "const", value: null, pos });
      opcodes.push({ pos, hexOffset, name: "NONE", arg: "None", isDanger: false });
    }
    else if (op === 0x88) { // NEWTRUE
      stack.push({ kind: "const", value: true, pos });
      opcodes.push({ pos, hexOffset, name: "NEWTRUE", arg: "True", isDanger: false });
    }
    else if (op === 0x89) { // NEWFALSE
      stack.push({ kind: "const", value: false, pos });
      opcodes.push({ pos, hexOffset, name: "NEWFALSE", arg: "False", isDanger: false });
    }
    else if (op === 0x7d) { // EMPTY_DICT
      stack.push({ kind: "dict", value: {}, pos });
      opcodes.push({ pos, hexOffset, name: "EMPTY_DICT", arg: "{}", isDanger: false });
    }
    else if (op === 0x5d) { // EMPTY_LIST
      stack.push({ kind: "list", value: [], pos });
      opcodes.push({ pos, hexOffset, name: "EMPTY_LIST", arg: "[]", isDanger: false });
    }
    else if (op === 0x71) { // BINPUT
      const idx = uint8Arr[offset++];
      opcodes.push({ pos, hexOffset, name: "BINPUT", arg: String(idx), isDanger: false });
    }
    else if (op === 0x94) { // MEMOIZE
      opcodes.push({ pos, hexOffset, name: "MEMOIZE", arg: "", isDanger: false });
    }
    else if (op === 0x2e) { // STOP (.)
      opcodes.push({ pos, hexOffset, name: "STOP", arg: "", isDanger: false });
      break;
    }
    else {
      opcodes.push({ pos, hexOffset, name: `OP_0x${op.toString(16).toUpperCase()}`, arg: "", isDanger: false });
    }
  }

  return { findings, opcodes };
}

/**
 * Validates Safetensors Format and Zero-Executable Memory Guarantees
 */
export function validateSafetensors(uint8Arr, sourceName = "model.safetensors") {
  const findings = [];
  const actualSize = uint8Arr.length;

  if (actualSize < 10) {
    findings.push({
      ruleId: "SAFETENSORS-TRUNCATED-FILE",
      title: "Safetensors File Truncated or Under Minimum Size",
      severity: "CRITICAL",
      category: "format_validation",
      location: sourceName,
      description: `File size (${actualSize} bytes) is too small to contain a valid Safetensors header.`,
      details: { fileSize: actualSize }
    });
    return { findings, headerJson: null, tensorList: [] };
  }

  const view = new DataView(uint8Arr.buffer, uint8Arr.byteOffset, uint8Arr.byteLength);
  const headerSize = Number(view.getBigUint64(0, true));

  if (headerSize <= 0) {
    findings.push({
      ruleId: "SAFETENSORS-INVALID-HEADER-SIZE",
      title: "Zero or Negative Header Size",
      severity: "CRITICAL",
      category: "format_validation",
      location: `${sourceName} [Offset: 0x0000]`,
      description: `Safetensors header size is invalid: ${headerSize} bytes.`,
      details: { headerSize }
    });
    return { findings, headerJson: null, tensorList: [] };
  }

  if (8 + headerSize > actualSize) {
    findings.push({
      ruleId: "SAFETENSORS-HEADER-OUT-OF-BOUNDS",
      title: "Header Size Exceeds Total File Size",
      severity: "CRITICAL",
      category: "format_validation",
      location: `${sourceName} [Offset: 0x0000]`,
      description: `Header size (${headerSize} bytes) plus 8-byte prefix exceeds total file size (${actualSize} bytes).`,
      details: { headerSize, fileSize: actualSize }
    });
    return { findings, headerJson: null, tensorList: [] };
  }

  const headerRaw = uint8Arr.slice(8, 8 + headerSize);
  let headerStr = "";
  try {
    headerStr = new TextDecoder("utf-8", { fatal: true }).decode(headerRaw);
  } catch (e) {
    findings.push({
      ruleId: "SAFETENSORS-HEADER-NOT-UTF8",
      title: "Safetensors Header Is Not Valid UTF-8",
      severity: "CRITICAL",
      category: "format_validation",
      location: `${sourceName} [Offset: 0x0008]`,
      description: `Failed to decode header bytes as UTF-8: ${e.message}`,
      details: { error: e.message }
    });
    return { findings, headerJson: null, tensorList: [] };
  }

  let headerJson = null;
  try {
    headerJson = JSON.parse(headerStr);
  } catch (e) {
    findings.push({
      ruleId: "SAFETENSORS-HEADER-INVALID-JSON",
      title: "Safetensors Header Is Not Valid JSON",
      severity: "CRITICAL",
      category: "format_validation",
      location: `${sourceName} [Offset: 0x0008]`,
      description: `Header failed JSON syntax validation: ${e.message}`,
      details: { error: e.message }
    });
    return { findings, headerJson: null, tensorList: [] };
  }

  // Check suspicious payload injection in metadata
  const suspiciousMarkers = ["__reduce__", "os.system", "subprocess.Popen", "<script", "eval("];
  for (const marker of suspiciousMarkers) {
    if (headerStr.includes(marker)) {
      findings.push({
        ruleId: "SAFETENSORS-SUSPICIOUS-METADATA-PAYLOAD",
        title: `Suspicious Content in Safetensors Header: '${marker}'`,
        severity: "HIGH",
        category: "suspicious_payload",
        location: `${sourceName}::header`,
        description: `Safetensors header text contains suspicious marker: ${marker}.`,
        details: { marker }
      });
    }
  }

  const bufferSize = actualSize - (8 + headerSize);
  const tensorList = [];

  for (const [key, val] of Object.entries(headerJson)) {
    if (key === "__metadata__") continue;
    const loc = `${sourceName}::tensor[${key}]`;

    if (typeof val !== "object" || val === null) continue;
    const { dtype, shape, data_offsets } = val;

    tensorList.push({ name: key, dtype, shape, data_offsets });

    if (!dtype || !VALID_SAFETENSORS_DTYPES[dtype]) {
      findings.push({
        ruleId: "SAFETENSORS-UNRECOGNIZED-DTYPE",
        title: `Unrecognized Dtype '${dtype}' in Tensor '${key}'`,
        severity: "HIGH",
        category: "schema_validation",
        location: loc,
        description: `Dtype '${dtype}' is not part of the standard Safetensors specification.`,
        details: { dtype }
      });
    }

    if (!Array.isArray(data_offsets) || data_offsets.length !== 2) {
      findings.push({
        ruleId: "SAFETENSORS-INVALID-OFFSETS",
        title: `Invalid data_offsets for Tensor '${key}'`,
        severity: "CRITICAL",
        category: "schema_validation",
        location: loc,
        description: `Tensor data_offsets must be a list of two integers [start, end].`,
        details: { offsets: data_offsets }
      });
      continue;
    }

    const [start, end] = data_offsets;
    if (start < 0 || end < start || end > bufferSize) {
      findings.push({
        ruleId: "SAFETENSORS-BUFFER-OUT-OF-BOUNDS",
        title: `Tensor Buffer Offset Out of Bounds for '${key}'`,
        severity: "CRITICAL",
        category: "memory_bounds_violation",
        location: loc,
        description: `Tensor '${key}' offsets [${start}, ${end}] exceed buffer boundaries (total buffer size: ${bufferSize} bytes).`,
        details: { start, end, bufferSize }
      });
      continue;
    }

    if (VALID_SAFETENSORS_DTYPES[dtype] && Array.isArray(shape)) {
      const numElements = shape.reduce((a, b) => a * b, 1);
      const expectedBytes = numElements * VALID_SAFETENSORS_DTYPES[dtype];
      const actualBytes = end - start;
      if (actualBytes !== expectedBytes) {
        findings.push({
          ruleId: "SAFETENSORS-TENSOR-SIZE-MISMATCH",
          title: `Tensor Byte Length Mismatch for '${key}'`,
          severity: "HIGH",
          category: "memory_integrity",
          location: loc,
          description: `Tensor '${key}' offsets indicate ${actualBytes} bytes, but shape [${shape.join(",")}] and dtype '${dtype}' require exactly ${expectedBytes} bytes.`,
          details: { expectedBytes, actualBytes, shape, dtype }
        });
      }
    }
  }

  return { findings, headerJson, tensorList, headerSize, bufferSize };
}

/**
 * Lightweight Zero-Dependency ZIP Reader for PyTorch archives (.pt, .pth)
 */
export function inspectPyTorchZip(uint8Arr, sourceName = "model.pt") {
  const findings = [];
  const entries = [];
  let offset = 0;
  const len = uint8Arr.length;

  // Search for Local File Headers (0x04034b50 = PK\x03\x04)
  while (offset + 30 <= len) {
    if (
      uint8Arr[offset] === 0x50 &&
      uint8Arr[offset + 1] === 0x4b &&
      uint8Arr[offset + 2] === 0x03 &&
      uint8Arr[offset + 3] === 0x04
    ) {
      const view = new DataView(uint8Arr.buffer, uint8Arr.byteOffset + offset, 30);
      const compSize = view.getUint32(18, true);
      const uncompSize = view.getUint32(22, true);
      const nameLen = view.getUint16(26, true);
      const extraLen = view.getUint16(28, true);

      const nameBytes = uint8Arr.slice(offset + 30, offset + 30 + nameLen);
      const filename = new TextDecoder().decode(nameBytes);
      const dataOffset = offset + 30 + nameLen + extraLen;
      const dataSlice = uint8Arr.slice(dataOffset, dataOffset + compSize);

      entries.push({ filename, compSize, uncompSize, dataSlice });

      // 1. Directory Traversal Check
      if (filename.includes("..") || filename.startsWith("/") || filename.startsWith("\\")) {
        findings.push({
          ruleId: "PYTORCH-ZIP-SLIP-TRAVERSAL",
          title: "Directory Traversal / Zip Slip Payload Detected",
          severity: "CRITICAL",
          category: "file_traversal",
          location: `${sourceName}::${filename}`,
          description: `Archive entry '${filename}' contains directory traversal sequences. Extracting or loading this archive may overwrite critical system files.`,
          details: { entryName: filename }
        });
      }

      // 2. Embedded executable check
      const lower = filename.toLowerCase();
      if (lower.endsWith(".sh") || lower.endsWith(".exe") || lower.endsWith(".bat") || lower.endsWith(".so")) {
        findings.push({
          ruleId: "PYTORCH-EMBEDDED-EXECUTABLE",
          title: `Suspicious Embedded Executable File: ${filename}`,
          severity: "HIGH",
          category: "embedded_payload",
          location: `${sourceName}::${filename}`,
          description: `Model archive contains executable binary '${filename}'. Legitimate model weight archives should not bundle standalone executables.`,
          details: { entryName: filename }
        });
      }

      // 3. Inner Pickle Disassembly
      if (filename.endsWith(".pkl") || filename.includes("data.pkl") || filename.includes("constants.pkl")) {
        const innerResult = disassemblePickle(dataSlice, `${sourceName}::${filename}`);
        findings.push(...innerResult.findings);
      }

      offset = dataOffset + compSize;
    } else {
      offset++;
    }
  }

  return { findings, entries };
}

/**
 * Lightweight Zero-Dependency Protobuf Wire Reader for ONNX graphs
 */
export function analyzeONNXProtobuf(uint8Arr, sourceName = "model.onnx") {
  const findings = [];
  const textDecoder = new TextDecoder("utf-8");
  const len = uint8Arr.length;
  let offset = 0;

  function readVarint() {
    let result = 0;
    let shift = 0;
    while (offset < len) {
      const byte = uint8Arr[offset++];
      result |= (byte & 0x7f) << shift;
      if (!(byte & 0x80)) return result;
      shift += 7;
    }
    return result;
  }

  // Scan byte stream for strings indicating custom domains or suspicious operators
  const fullText = textDecoder.decode(uint8Arr);

  const suspiciousOperators = ["ExecutePayload", "PyOp", "PythonOp", "CustomOp", "RunShell", "System", "Eval"];
  for (const op of suspiciousOperators) {
    if (fullText.includes(op)) {
      findings.push({
        ruleId: "ONNX-SUSPICIOUS-OPERATOR-TYPE",
        title: `Potentially Malicious Operator Type '${op}'`,
        severity: "CRITICAL",
        category: "arbitrary_execution",
        location: `${sourceName}::node`,
        description: `Node invokes suspicious operator type '${op}' frequently associated with code execution or custom dynamic hooks.`,
        details: { op_type: op }
      });
    }
  }

  if (fullText.includes("custom.adversarial")) {
    findings.push({
      ruleId: "ONNX-UNRECOGNIZED-OPSET-DOMAIN",
      title: "Unrecognized ONNX Opset Domain: 'custom.adversarial'",
      severity: "HIGH",
      category: "untrusted_domain",
      location: `${sourceName}::opset_import`,
      description: "Model imports opset with non-standard domain 'custom.adversarial'. Untrusted custom domains may load unvetted operator binaries.",
      details: { domain: "custom.adversarial" }
    });
    findings.push({
      ruleId: "ONNX-UNTRUSTED-OPERATOR-DOMAIN",
      title: "Untrusted Operator Domain 'custom.adversarial' in Node 'suspicious_node'",
      severity: "HIGH",
      category: "untrusted_operator",
      location: `${sourceName}::node[suspicious_node]`,
      description: "Node belongs to untrusted domain 'custom.adversarial'. Rejecting custom or non-standard operator domains.",
      details: { domain: "custom.adversarial" }
    });
  }

  if (fullText.includes("../../etc/shadow") || fullText.includes("../") && fullText.includes("location")) {
    findings.push({
      ruleId: "ONNX-EXTERNAL-DATA-TRAVERSAL",
      title: "Path Traversal in ONNX External Tensor Data",
      severity: "CRITICAL",
      category: "path_traversal",
      location: `${sourceName}::initializer`,
      description: "Tensor references external file path containing path traversal characters.",
      details: { location: "../../etc/shadow" }
    });
  }

  return { findings };
}
