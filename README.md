# ida-llm-exporter

Offline IDA export toolkit for LLM-assisted reverse engineering.

This repository contains an **IDA Pro 9.2** Python script that exports a rich static snapshot of an IDB into a single bundle (`ida_export.zip`).  
The bundle is designed to be uploaded to large language models (LLMs) such as ChatGPT / Claude for offline analysis, without giving the model direct access to your IDA instance.

---

## Background

The idea for this project comes from Check Point Research’s article:

> Generative AI for reverse engineering – *Offline IDA export pipeline: reverse engineering with AI in the cloud*  
> https://research.checkpoint.com/2025/generative-ai-for-reverse-engineering/

After reading it I thought the workflow was very interesting, so I implemented my own export script to try a similar approach:  
export everything important from IDA, zip it, and let an LLM reason over the archive.

---

## Features

- Single Python script, no plugin build required.
- Designed and tested for **IDA Pro 9.2**.
- Exports:
  - metadata, segments, imports, exports;
  - functions with instructions, basic blocks, xrefs, comments and Hex-Rays decompilation (if available);
  - strings and their references;
  - global data and references;
  - optional user-defined local types (structs/enums/typedefs only);
  - optional assembly slices (by ranges / by functions / all code segments);
  - a copy of the original sample.
- Outputs JSON / JSONL / plain text that is friendly for LLM prompts.

---

## Exported bundle layout

All files are written under the directory of the input binary in `ida_export/`, then zipped into `ida_export.zip`.

    ida_export.zip
    ├─ meta.json              # basic info (file name, hashes, image base, arch, IDA version, timestamp, etc.)
    ├─ segments.json          # segment layout (name, start/end, size, class, permissions, file offset)
    ├─ imports.json           # import modules and imported APIs (name / ordinal / EA)
    ├─ exports.json           # export table (index, ordinal, EA, name)
    ├─ functions.jsonl        # NDJSON: functions with xrefs, basic blocks, instructions, comments, bytes_concat, decomp_path
    ├─ index.json             # function index (by_name, by_ea -> line index in functions.jsonl)
    ├─ strings.jsonl          # list of strings and their references
    ├─ data.jsonl             # globals / named data items and their references
    ├─ data_index.json        # data index (by_name -> EA)
    ├─ types.json             # (optional) user-defined local types (structs/enums/typedefs only, no system TIL types)
    ├─ asm_index.json         # (optional) index of exported assembly units (ranges / functions / segments)
    ├─ asm/                   # (optional) flat assembly slices in text form
    │   ├─ func_*.asm         # disassembly for specific functions
    │   ├─ range_*.asm        # disassembly for user-specified address ranges
    │   └─ seg_*.asm          # disassembly for full code segments
    ├─ decomp/                # Hex-Rays pseudo-C per function (if Hex-Rays is available)
    │   └─ <name>_<ea>.c
    └─ sample.bin             # the original malware sample itself (byte-for-byte copy)

The formats are intentionally simple JSON / JSONL so that prompts can quote exact EAs and fields when talking to an LLM.

---

## Requirements

- **IDA Pro 9.2** (the script uses 9.2 APIs; older versions are not supported).
- The Python 3 environment that ships with IDA 9.2.
- Optional: Hex-Rays decompiler for `decomp/*.c`.

---

## Installation

1. Clone this repository.
2. Copy the main script (for example `ida-llm-exporter.py`) to a location accessible by IDA:
   - e.g. your IDA `python` directory, or
   - any folder you can browse to from `File -> Script file…`.

No plugin registration is needed; it is just a Python script.

---

## Usage

1. Open your sample in **IDA Pro 9.2** and wait until auto-analysis finishes.

2. In IDA, run:

   - `File -> Script file…`
   - Select `ida-llm-exporter.py`.

3. Watch the output window and answer the prompts:

   - The script always exports:
     - `meta.json`, `segments.json`, `imports.json`, `exports.json`
     - `functions.jsonl`, `index.json`
     - `strings.jsonl`
     - `data.jsonl`, `data_index.json`
     - `sample.bin`

   - If user-defined local types are detected, you will be asked:

     - Whether to export them to `types.json`.  
       This is only useful if you created your own structs/enums/typedefs for this sample.

   - For assembly export you will see:

     - A yes/no question: whether you want to export flat disassembly.
     - If yes, you choose one mode:
       1. By address ranges — you type ranges like  
          `0x140032E5A-0x140032E90,0x140040000-0x140040100`  
          (end address is inclusive in the UI).
       2. By functions — you type function names or start EAs, e.g.  
          `start,sub_1400300B8,0x140012340`.  
          If an EA has code but no function yet, the script can create a function there.
       3. All code segments — all segments with class `"CODE"` are exported.

4. When finished, you should see messages similar to:

    Export directory: D:\samples\test\ida_export  
    Wrote meta.json  
    Wrote functions.jsonl and index.json, total 123 functions  
    Wrote strings.jsonl, total 456 strings  
    Wrote data.jsonl and data_index.json, total 78 data items  
    No user-defined local types found, skipping types.json  
    Wrote asm_index.json with 5 units  
    Copied sample to sample.bin  
    Created archive D:\samples\test\ida_export.zip  
    Export completed in 2.3 seconds  

5. Upload `ida_export.zip` to your LLM of choice (ChatGPT, Claude, etc.), and use a strict prompt that:

   - treats the archive as the **only** source of truth,
   - quotes evidence (file + EA + snippet) for any numeric / structural claim,
   - avoids fabricating missing values,
   - prefers “not found + explanation” over guessing.

The Check Point article linked above has good ideas for designing such prompts (e.g. evidence-first, local-first, no cosmetic transformations).

---

## Notes & Limitations

- Only tested on **IDA Pro 9.2**. Other versions may have API differences.
- The script exports **static** data only:
  - it does not execute the sample,
  - it does not connect to the network,
  - it does not perform dynamic tracing.
- Hex-Rays is optional: if decompilation fails or is not available, those functions simply will not have `decomp_path` in `functions.jsonl`.
- Exporting all code segments and detailed instructions on very large binaries can produce large files; use address/function-based assembly export when you only care about specific regions.

---

## Legal & Ethical Notice

This project is intended for legitimate security research and malware analysis of software **you are authorized to analyze**.

Do not use it for illegal purposes.  
The author are not responsible for any misuse of this tool.

---

## License

MIT License

Copyright (c) 2025 Augenstern

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
