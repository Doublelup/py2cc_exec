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
A -> B: challenge(nonce_0, sequence=0)
B -> A: exec(command_0, nonce_0, sequence=0, signature)
A -> B: result_0 + nonce_1
B -> A: exec(command_1, nonce_1, sequence=1, signature)
```

签名覆盖协议域标识、版本、序号、请求 UUID、nonce、完整命令和超时。A 在验签成功后、执行命令前立即作废当前 nonce。认证失败只关闭当前 TCP 会话，监听服务继续运行。

连接可能在命令执行完成后、结果到达 B 前中断，因此 B 无法确定这类命令是否已经执行。客户端不会自动重试，非幂等命令也不应由调用方盲目重试。
