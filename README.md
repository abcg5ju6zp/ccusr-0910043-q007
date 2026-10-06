# Sanic 服务框架

本项目提供异步 HTTP 服务、路由、蓝图、中间件、信号、后台任务和工作进程管理能力。生产源码位于 `sanic/`，核心回归测试位于 `tests/`。

## 安装

`python3 -m pip install --break-system-packages --no-build-isolation -e '.[test]'`

## 测试

`python3 -m pytest -q`

## 构建

`python3 -m compileall -q sanic`

`python3 -m build --wheel --no-isolation`

## 使用

应用通过 `Sanic` 创建服务，可使用本地测试客户端验证请求、响应和生命周期行为。

## 不可变制品分发

签名规则文件等制品要求“发布的字节永不改变”。普通静态文件直接按路径读取，发布方原地替换文件后，持有旧 ETag 的客户端用 `Range` 续传会拼出新旧混合的内容。制品 API 则在发布时把可见区间封存为**不可变版本**：

```python
from sanic import Sanic

app = Sanic("edge")
registry = app.artifact("/dist", "/var/lib/edge/artifacts")

await app.publish_artifact("rules.sig", "/srv/rules/current.sig")
```

发布时固定摘要（默认 SHA-256）、字节长度与可见区间 `[start, end)`，字节复制到内容寻址的私有存储，路径别名只原子指向一个版本。

- **请求期间钉住版本**：请求开始后即使别名已切到新版本，或该版本被并发撤回，仍继续读取原对象（撤回先打开句柄再删除文件，旧 inode由打开的描述符继续提供）。
- **条件请求**：强 ETag（`ETag`），支持 `If-Match`（412）、`If-None-Match`（304）、`If-Modified-Since`、`If-Unmodified-Since`。
- **续传不混版**：`If-Range` 始终与别名当前指向的版本比较；旧 ETag 失配时返回当前完整对象（200），绝不拼接；要显式续传旧版本须带匹配的 `If-Match`。
- **Range**：支持单段 206 与多段 `multipart/byteranges`（重叠区间自动合并、精确 `Content-Length`），越界返回 416。
- **外部替换源文件无影响**：服务字节来自发布时封存的只读快照；打开时校验长度，全量读取与流式读取均校验摘要，存储 blob 被篡改返回 500 而非错误字节。
- **并发撤回**：`await app.revoke_artifact("rules.sig")` 或 `revoke_artifact(version=...)`；共享 blob 的多个别名按引用计数，最后一个引用撤完才删除字节。
- **重启恢复**：索引（别名映射 + 版本元数据）原子写入存储目录的 `artifact-index.json`；挂载时注册 `before_server_start` 恢复，并在每次请求前以一次 `stat` 检测索引变更，跨 worker 的发布/撤回也能即时可见。
- **访问日志**：记录版本依据 `alias@<摘要前缀>`，不记录本机绝对路径。

也可以直接使用底层注册表：`from sanic import ArtifactRegistry, ArtifactVersion`。相关回归见 `tests/test_artifacts.py`。

