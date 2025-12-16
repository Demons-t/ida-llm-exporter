# ida-llm-exporter

用于 LLM 辅助逆向工程的离线 IDA 导出工具。

本仓库包含一个 **IDA Pro 9.2** 的 Python 脚本，用于将 IDB 中的静态分析结果导出为一个完整的离线快照，并打包成单一文件（`ida_export.zip`）。  
该导出包可上传至 ChatGPT、Claude 等大语言模型（LLM）进行**离线分析**，无需让模型直接访问你的 IDA 实例。

---

## 项目背景

本项目的灵感来自 Check Point Research 的文章：

> Generative AI for reverse engineering – *Offline IDA export pipeline: reverse engineering with AI in the cloud*  
> https://research.checkpoint.com/2025/generative-ai-for-reverse-engineering/

阅读该文章后，我觉得挺有意思，就实现了一个 IDA 导出脚本，尝试类似的思路：  
将 IDA 中所有重要的静态信息导出、打包成 zip，然后让 LLM 在完整上下文下对这些数据进行推理分析。

---

## 功能特性

- 单一 Python 脚本，无需编译插件。
- 专为 **IDA Pro 9.2** 设计并测试。
- 可导出以下内容：
  - 元数据、段信息、导入表、导出表；
  - 函数信息（包含指令、基本块、交叉引用、注释及 Hex-Rays 反编译结果（如果可用））；
  - 字符串及其引用关系；
  - 全局数据与命名数据项及其引用；
  - 可选：用户自定义的本地类型（仅 struct / enum / typedef，不包含系统 TIL 类型）；
  - 可选：汇编代码切片（按地址范围 / 按函数 / 按代码段）；
  - 原始样本文件的完整拷贝。
- 输出格式为 JSON / JSONL / 纯文本，便于在提示词中引用精确 EA 与字段。

---

## 导出包结构

所有文件将写入输入二进制所在目录下的 `ida_export/`，随后打包为 `ida_export.zip`。

    ida_export.zip
    ├─ meta.json              # 基本信息（文件名、hash、image base、架构、IDA 版本、时间戳等）
    ├─ segments.json          # 段布局（名称、起止地址、大小、类型、权限、文件偏移）
    ├─ imports.json           # 导入模块及 API（名称 / ordinal / EA）
    ├─ exports.json           # 导出表（索引、ordinal、EA、名称）
    ├─ functions.jsonl        # NDJSON：函数信息（xrefs、基本块、指令、注释、bytes_concat、decomp_path）
    ├─ index.json             # 函数索引（by_name、by_ea -> functions.jsonl 行号）
    ├─ strings.jsonl          # 字符串列表及其引用
    ├─ data.jsonl             # 全局数据 / 命名数据项及其引用
    ├─ data_index.json        # 数据索引（by_name -> EA）
    ├─ types.json             # （可选）用户定义的本地类型（struct / enum / typedef，不含系统类型）
    ├─ asm_index.json         # （可选）汇编导出单元索引（范围 / 函数 / 段）
    ├─ asm/                   # （可选）纯汇编切片
    │   ├─ func_*.asm         # 指定函数的反汇编
    │   ├─ range_*.asm        # 用户指定地址范围的反汇编
    │   └─ seg_*.asm          # 整个代码段的反汇编
    ├─ decomp/                # Hex-Rays 伪代码（如果可用）
    │   └─ <name>_<ea>.c
    └─ sample.bin             # 原始样本文件（逐字节拷贝）

这些格式保持为简单的 JSON / JSONL，以便在与 LLM 交互时，能够精确引用 EA 和字段作为证据。

---

## 环境要求

- **IDA Pro 9.2**（脚本使用 9.2 API）。
- IDA 9.2 自带的 Python 3 环境。
- 可选：Hex-Rays 反编译器（用于生成 `decomp/*.c`）。

---

## 安装方式

1. 克隆本仓库。
2. 将主脚本（例如 `ida-llm-exporter.py`）复制到 IDA 可访问的位置：
   - 例如 IDA 的 `python` 目录，或
   - 任意可通过 `File -> Script file…` 浏览到的目录。

无需进行插件注册，该脚本为普通 Python 脚本。

---

## 使用方法

1. 使用 **IDA Pro 9.2** 打开目标样本，并等待自动分析完成。

2. 在 IDA 中执行：

   - `File -> Script file…`
   - 选择 `ida-llm-exporter.py`

3. 观察输出窗口并按提示操作：

   - 脚本始终会导出：
     - `meta.json`, `segments.json`, `imports.json`, `exports.json`
     - `functions.jsonl`, `index.json`
     - `strings.jsonl`
     - `data.jsonl`, `data_index.json`
     - `sample.bin`

   - 若检测到用户自定义的本地类型，将询问：
     - 是否导出为 `types.json`  
       仅当你为该样本手动补充了结构体 / 枚举 / typedef 时才有意义。

   - 关于汇编导出，将依次询问：
     - 是否导出纯反汇编代码；
     - 若选择是，则需选择导出模式：
       1. 按地址范围导出 —— 输入如  
          `0x140032E5A-0x140032E90,0x140040000-0x140040100`  
          （UI 中结束地址为包含关系）。
       2. 按函数导出 —— 输入函数名或起始 EA，例如  
          `start,sub_1400300B8,0x140012340`。  
          若指定 EA 处存在代码但尚未定义函数，脚本可在该处创建函数。
       3. 导出所有代码段 —— 导出所有 class 为 `"CODE"` 的段。

4. 完成后，你应看到类似输出：

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

5. 将生成的 `ida_export.zip` 上传至你选择的 LLM（ChatGPT、Claude 等），并配合**严格的提示词**使用：

   - 将导出包视为**唯一可信数据源**；
   - 所有数值 / 结构性结论必须引用证据（文件 + EA + 片段）；
   - 避免编造缺失信息；
   - 优先使用“未找到 + 解释原因”，而非猜测。

Check Point 的文章中对提示词设计（如 evidence-first、local-first、no cosmetic transformations）给出了非常有价值的思路。

---

## 注意事项与限制

- 仅在 **IDA Pro 9.2** 上测试，其他版本可能存在 API 不兼容。
- 脚本仅导出**静态分析数据**：
  - 不执行样本；
  - 不进行网络连接；
  - 不包含动态跟踪。
- Hex-Rays 为可选组件：若反编译失败或不可用，对应函数将不会生成 `decomp_path`。
- 对于体积较大的二进制，导出全部代码段和详细指令可能产生较大的文件；若只关注特定区域，建议使用按地址 / 按函数的汇编导出模式。

---

## 法律与伦理声明

本项目仅用于**合法授权范围内的软件安全研究与恶意代码分析**。

请勿将其用于任何非法用途。  
作者不对任何形式的滥用行为承担责任。

---

## 许可证

MIT License
