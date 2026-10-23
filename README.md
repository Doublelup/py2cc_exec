# Remote Exec Lab

这是一个用于网络课程实验的最小远程 Bash 执行协议：A 端保存 B 的 Ed25519 公钥，B 使用私钥签署每一条命令。服务端为每个请求发放一次性 nonce，并在结果中返回下一个 nonce，从而在一条 TCP 长连接中连续执行命令。

它不是交互式终端：每条请求启动一个独立的非交互 Bash 进程，命令结束后统一返回 stdout、stderr 和退出码。应用层只认证 B 和命令内容；传输保密、A 的身份以及返回结果的完整性依赖受信任的 VS Code 隧道。

## 环境初始化

项目使用 `uv` 管理 `.venv` 和 `uv.lock`。项目配置优先从清华 PyPI 镜像下载依赖，镜像缺包时回退到官方 PyPI。

```bash
uv sync
```

运行测试：

```bash
uv run pytest
```

## 生成密钥

默认生成带口令保护的私钥：

```bash
uv run py2cc_keygen
```

自动化实验可以显式生成无口令私钥：

```bash
uv run py2cc_keygen --no-passphrase
```

生成结果为：

- `keys/client.key`：只部署到 B。
- `keys/client.pub`：部署到 A。

工具拒绝覆盖已有密钥。

## 同一台主机测试

终端 A：

```bash
uv run py2cc_server \
  --public-key keys/client.pub \
  --host 127.0.0.1 \
  --port 9000 \
  --workdir "$PWD" \
  --verbose
```

终端 B 执行单条命令：

```bash
uv run py2cc_client \
  --private-key keys/client.key \
  --host 127.0.0.1 \
  --port 9000 \
  --command 'uname -a; printf "cwd=%s\\n" "$PWD"'
```

终端 B 连续执行多条命令：

```bash
uv run py2cc_client --private-key keys/client.key --host 127.0.0.1 --port 9000
```

输入 `:quit` 或按 `Ctrl-D` 退出客户端。

## MCP 接入 Codex

项目同时提供本地 stdio MCP server。它在进程生命周期内保留一个
`RemoteExecClient`，因此连续的工具调用会复用 TCP 连接和 nonce 链。

从 `py2cc_exec` 目录手动启动：

```bash
uv run py2cc_mcp \
  --private-key keys/client.key \
  --host 127.0.0.1 \
  --port 18003 \
  --default-timeout 30
```

私钥必须是 `py2cc_keygen --no-passphrase` 生成的无口令 PEM，且权限不得宽于
`600`。MCP 使用 stdin/stdout 传输协议，因此不能在启动时交互输入私钥口令。

若目录结构为：

```text
py2cc/
├── .codex/config.toml
└── py2cc_exec/
```

外层项目配置会以端口 `18003` 启动这个 MCP server。先同步依赖并确认配置：

```bash
cd py2cc/py2cc_exec
uv sync
cd ..
codex
```

首次从外层 `py2cc` 目录启动 Codex 时，需要将该项目标记为可信；项目级配置只在
新会话启动时加载。`codex mcp list` 主要用于管理用户级配置，在部分版本中不会
列出项目级 MCP，因此应在新会话中实际调用一次 `run_command` 来确认连接。

外层 `.codex/config.toml` 的配置如下。相对路径以 `.codex/` 为基准，因此
`cwd = ".."` 指向外层项目目录：

```toml
[mcp_servers.py2cc]
command = "uv"
args = [
  "run",
  "--project",
  "py2cc_exec",
  "py2cc_mcp",
  "--private-key",
  "py2cc_exec/keys/client.key",
  "--host",
  "127.0.0.1",
  "--port",
  "18003",
]
cwd = ".."
startup_timeout_sec = 20
tool_timeout_sec = 330
```

在可信的 `py2cc` 项目中启动新 Codex 会话后，可使用：

- `run_command(command, timeout_seconds)`：执行一条命令。
- `run_commands(commands, timeout_seconds, stop_on_error)`：在同一连接中顺序执行多条命令。
- `remote_read(file_path, offset, limit)`：读取远端 UTF-8 文本窗口，并返回整文件 SHA-256。
- `remote_edit(file_path, old_string, new_string, expected_sha256, replace_all)`：仅在哈希仍匹配时精确替换文本。
- `remote_write(file_path, content)`：创建或完整覆盖远端 UTF-8 文本文件。

命令工具返回结构化的状态、退出码、stdout、stderr、截断标志和
`outcome_unknown`。若 `outcome_unknown` 为 `true`，不要自动重试原命令。
命令工具仍然没有 PTY，不适合 `vim`、`top`、密码提示或交互式 REPL。

文件工具的典型流程是先读取再编辑：

```text
remote_read("src/example.py")
  -> content + sha256
remote_edit("src/example.py", old_string, new_string, expected_sha256=sha256)
  -> replacements + 修改后的 sha256
```

如果文件在两次调用之间发生变化，`remote_edit` 返回 `stale_file`，且
`sha256` 为 `null`；调用方必须重新读取文件。三个文件工具的结果中始终存在
`sha256` 字段，成功时为操作后的整文件哈希，失败时为 `null`。
`remote_write` 不进行哈希前置校验，它表示调用方明确要求完整覆盖文件。

相对文件路径从 `py2cc_server --workdir` 解析，也可以传入绝对路径。服务端只处理
UTF-8 普通文件，默认文件大小上限为 1 MiB，可通过 `--max-file-bytes` 调整；
Read 每次最多返回 2000 行。写入使用同目录临时文件和原子替换，并保留已有文件权限。

## 两台主机和 VS Code 端口转发

1. 在 A 上启动服务，仍然只监听 `127.0.0.1:9000`。
2. 在连接到 A 的 VS Code 窗口中打开 Ports 面板，转发远端端口 `9000`。
3. VS Code 会在 B 上分配一个本地端口，例如 `41234`。
4. 在 B 上执行：

```bash
uv run py2cc_client \
  --private-key keys/client.key \
  --host 127.0.0.1 \
  --port 41234
```

不要把私钥复制到 A。若不用 VS Code 隧道，当前协议不会加密命令和输出，也不能让 B 验证 A 的身份。

## 协议概要

消息使用 4 字节大端长度前缀和 JSON 正文：

```text
A -> B: challenge(nonce_0, sequence=0, capabilities=[...])
B -> A: exec(command_0, nonce_0, sequence=0, signature)
A -> B: result_0 + nonce_1
B -> A: read_file/edit_file/write_file(..., nonce_1, sequence=1, signature)
A -> B: file_result_1 + nonce_2
```

签名覆盖协议域标识、版本、序号、请求 UUID、nonce 以及对应操作的全部参数。
A 在验签成功后、执行操作前立即作废当前 nonce。认证失败只关闭当前 TCP 会话，
监听服务继续运行。capabilities 为可选字段，因此新服务端仍兼容旧客户端；新客户端
连接没有 capabilities 的旧服务端时仍可执行命令，但文件工具会返回 `unsupported`。

连接可能在命令执行完成后、结果到达 B 前中断，因此 B 无法确定这类命令是否已经执行。客户端不会自动重试，非幂等命令也不应由调用方盲目重试。
