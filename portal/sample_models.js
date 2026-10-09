/**
 * Pre-baked Synthetic Benchmark Models (Base64 encoded)
 * Allows instant, zero-latency in-browser scanning without uploading local files.
 */

export const SAMPLE_MODELS = {
  "safe_model.safetensors": {
    name: "safe_model.safetensors",
    format: "safetensors",
    classification: "BENIGN",
    tag: "Standard Weights",
    description: "Fully compliant Hugging Face Safetensors model with valid JSON header and verified memory buffer bounds.",
    expectedVerdict: "APPROVED",
    expectedViolations: 0,
    base64: "6gAAAAAAAAB7IndlaWdodF8xIjp7ImR0eXBlIjoiRjMyIiwic2hhcGUiOlsyLDJdLCJkYXRhX29mZnNldHMiOlswLDE2XX0sIndlaWdodF8yIjp7ImR0eXBlIjoiRjMyIiwic2hhcGUiOlsyLDJdLCJkYXRhX29mZnNldHMiOlsxNiwzMl19LCJfX21ldGFkYXRhX18iOnsiZnJhbWV3b3JrIjoicHl0b3JjaCIsImZvcm1hdCI6InNhZmV0ZW5zb3JzIiwiZGVzY3JpcHRpb24iOiJCZW5pZ24gc3ludGhldGljIHRlc3QgbW9kZWwifX0AAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQ=="
  },
  "trojan_print.pkl": {
    name: "trojan_print.pkl",
    format: "pkl",
    classification: "MALICIOUS",
    tag: "Pickle Code Injection",
    description: "Synthetic Trojan model exploiting Python pickle __reduce__ to invoke builtins.print callback during deserialization.",
    expectedVerdict: "REJECTED",
    expectedViolations: 2,
    base64: "gASVVQAAAAAAAACMCGJ1aWx0aW5zlIwFcHJpbnSUk5SMOFNhZmUgVGVzdCBQYXlsb2FkIC0gRGVzZXJpYWxpemF0aW9uIEluc3BlY3Rpb24gVHJpZ2dlcmVklIWUUpQu"
  },
  "trojan_print.pt": {
    name: "trojan_print.pt",
    format: "pt",
    classification: "MALICIOUS",
    tag: "PyTorch Archive Trojan",
    description: "PyTorch ZIP archive bundling an inner data.pkl containing an injected __reduce__ callable probe.",
    expectedVerdict: "REJECTED",
    expectedViolations: 2,
    base64: "UEsDBBQAAAAIAASeSV3RnmdVBAAAAAIAAAAPAAAAYXJjaGl2ZS92ZXJzaW9uM+YCAFBLAwQUAAAACAAEnkldAZIcrwkAAAAHAAAAEQAAAGFyY2hpdmUvYnl0ZW9yZGVyy8ksKclJ5QIAUEsDBBQAAAAIAASeSV3BeNNQWwAAAGAAAAAQAAAAYXJjaGl2ZS9kYXRhLnBrbGtgmRrKAAE9HEmlmTklmXnFU3pYC4oy80qmTJ7SYxGcmJaqEJJaXKIQkFiZk5+YoqCr4JJanFqUmZiTWZVYkpmfp+CZV1yQmgxmhhRlpqenFqWmTGmdEjRFDwBQSwECFAAUAAAACAAEnkld0Z5nVQQAAAACAAAADwAAAAAAAAAAAAAAgAEAAAAAYXJjaGl2ZS92ZXJzaW9uUEsBAhQAFAAAAAgABJ5JXQGSHK8JAAAABwAAABEAAAAAAAAAAAAAAIABMQAAAGFyY2hpdmUvYnl0ZW9yZGVyUEsBAhQAFAAAAAgABJ5JXcF401BbAAAAYAAAABAAAAAAAAAAAAAAAIABaQAAAGFyY2hpdmUvZGF0YS5wa2xQSwUGAAAAAAMAAwC6AAAA8gAAAAAA"
  },
  "custom_op.onnx": {
    name: "custom_op.onnx",
    format: "onnx",
    classification: "MALICIOUS",
    tag: "Adversarial ONNX Node",
    description: "ONNX graph importing unauthorized 'custom.adversarial' opset domain and invoking high-risk 'ExecutePayload' operator.",
    expectedVerdict: "REJECTED",
    expectedViolations: 3,
    base64: "CAg6ShIRYWR2ZXJzYXJpYWxfZ3JhcGgKNRoPc3VzcGljaW91c19ub2RlIg5FeGVjdXRlUGF5bG9hZDoSY3VzdG9tLmFkdmVyc2FyaWFsQhYKEmN1c3RvbS5hZHZlcnNhcmlhbBAB"
  },
  "malformed.safetensors": {
    name: "malformed.safetensors",
    format: "safetensors",
    classification: "ANOMALOUS",
    tag: "Buffer Overflow Anomaly",
    description: "Safetensors file with out-of-bounds offset metadata (offsets: [0, 999999] vs 16-byte actual buffer length).",
    expectedVerdict: "REJECTED",
    expectedViolations: 1,
    base64: "TgAAAAAAAAB7IndlaWdodF9vb2IiOiB7ImR0eXBlIjogIkYzMiIsICJzaGFwZSI6IFsyLCAyXSwgImRhdGFfb2Zmc2V0cyI6IFswLCA5OTk5OTldfX0AAAAAAAAAAAAAAAAAAAAA"
  },
  "safe_model.pkl": {
    name: "safe_model.pkl",
    format: "pkl",
    classification: "BENIGN",
    tag: "Safe Weights Pickle",
    description: "Benign pickle weight checkpoint containing only verified float lists, dictionary structures, and primitives.",
    expectedVerdict: "APPROVED",
    expectedViolations: 0,
    base64: "gASVmAAAAAAAAAB9lCiMCm1vZGVsX25hbWWUjBVzeW50aGV0aWMtcmVzbmV0LXNhZmWUjAVlcG9jaJRLCowHd2VpZ2h0c5RdlChHP7mZmZmZmZpHP8mZmZmZmZpHP9MzMzMzMzNHP9mZmZmZmZpHP+AAAAAAAABljAZjb25maWeUfZQojAtoaWRkZW5fc2l6ZZRNAAGMBmxheWVyc5RLBHV1Lg=="
  },
  "safe_model.pt": {
    name: "safe_model.pt",
    format: "pt",
    classification: "BENIGN",
    tag: "Safe PyTorch Weights",
    description: "Compliant PyTorch ZIP archive with standard data.pkl weights and zero executable hooks.",
    expectedVerdict: "APPROVED",
    expectedViolations: 0,
    base64: "UEsDBBQAAAAIAASeSV3RnmdVBAAAAAIAAAAPAAAAYXJjaGl2ZS92ZXJzaW9uM+YCAFBLAwQUAAAACAAEnkldAZIcrwkAAAAHAAAAEQAAAGFyY2hpdmUvYnl0ZW9yZGVyy8ksKclJ5QIAUEsDBBQAAAAIAASeSV2PPuWpLQAAAD0AAAAQAAAAYXJjaGl2ZS9kYXRhLnBrbGtgmWrEAAG1U3p4chIrU4v0ylMz0zNKpsRO0XC3/wCRdHeAqnJ34IAwUov1AFBLAQIUABQAAAAIAASeSV3RnmdVBAAAAAIAAAAPAAAAAAAAAAAAAACAAQAAAABhcmNoaXZlL3ZlcnNpb25QSwECFAAUAAAACAAEnkldAZIcrwkAAAAHAAAAEQAAAAAAAAAAAAAAgAExAAAAYXJjaGl2ZS9ieXRlb3JkZXJQSwECFAAUAAAACAAEnkldjz7lqS0AAAA9AAAAEAAAAAAAAAAAAAAAgAFpAAAAYXJjaGl2ZS9kYXRhLnBrbFBLBQYAAAAAAwADALoAAADEAAAAAAA="
  },
  "safe_model.onnx": {
    name: "safe_model.onnx",
    format: "onnx",
    classification: "BENIGN",
    tag: "Safe ONNX Graph",
    description: "Standard ONNX model utilizing official 'ai.onnx' opset domain and legitimate 'Relu' computational node.",
    expectedVerdict: "APPROVED",
    expectedViolations: 0,
    base64: "CAg6KBIKc2FmZV9ncmFwaAoaGglyZWx1X25vZGUiBFJlbHU6B2FpLm9ubnhCCwoHYWkub25ueBAO"
  }
};

/**
 * Converts a base64 string to a Uint8Array
 */
export function base64ToUint8Array(b64) {
  const binaryString = atob(b64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}
