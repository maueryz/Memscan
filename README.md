<div align="center">

# 🔍 Memscan 内存检索工具

<img src="ico.png" width="128" alt="Memscan Logo" />

**Windows 应急响应内存检索工具** —— 全进程内存中快速定位恶意域名 / IP / 特征码，自动关联 IPv4 / IPv6 TCP 外联，在已知 IOC 的前提下最快发现可疑进程。

![Go](https://img.shields.io/badge/Go-1.20-00ADD8)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6)
![Size](https://img.shields.io/badge/Size-Single_EXE-2ea44f)

</div>

---

## 📌 工具定位

一句话：**已知 IOC → 定位到进程 → 外联核实**。

Memscan 负责在内存里找到“已知的坏东西”落在哪个进程；连接细节交给 TCPView 等专业工具核实。它不追求功能大而全，只追求在应急场景下**快、准、省事**，单文件免安装、隔离网即插即用。

## ✨ 核心功能

- **全进程内存扫描**：扫描可读写（RW）/ 可读可执行（RWX）区域，**真实命中数完整统计**，不做截断
- **多编码关键词搜索**：UTF-8 / UTF-16LE / UTF-16BE / GBK / Big5 / Shift-JIS，命中后按对应编码解码上下文，中文直接可读
- **网络外联关联**：自动抓取进程 TCP 外联连接（IPv4 + IPv6），联网进程以红色 `<!>` 标记
- **懒加载分页展示**：展开结果每页 5 条，`上一页 / 下一页` 翻页，翻页与折叠即时释放资源，老机器不卡顿
- **结果实时过滤**：支持进程名 / PID 过滤，回车或点击“过滤”按钮生效，纯鼠标可用
- **TXT 审计报告导出**：进程名 / PID / 路径 / 命中总数 / 外联地址（本地 -> 远端逐条列出）/ 匹配编码 / 匹配上下文
- **CLI 交互模式**：双击命令行版直接进入 `Memscan>` 交互终端，可连续搜索；也支持脚本化一次性调用
- **老系统兼容**：Windows Server 2008 可运行；中文字体自动回退、控制台自动切换 UTF-8、GUI 无黑框、带自定义图标

## 🧠 多编码搜索

| 编码 | 适用场景 | 默认启用 |
| --- | --- | --- |
| UTF-8 | 现代应用、浏览器、Electron | ✅ |
| UTF-16LE | Windows 原生程序、微信等 | 可选 |
| UTF-16BE | 大端存储文本（关键词含非 ASCII 字符时生效） | 可选 |
| GBK | 老国产软件 | 可选 |
| Big5 | 繁体中文软件 | 可选 |
| Shift-JIS | 日文软件 | 可选 |

GUI 通过“编码”下拉勾选启用（变更后自动重扫）；CLI 默认仅 UTF-8，加 `-a` 参数全量扫描。

## 🖥️ 命令行模式

入口规则统一为：**`cli` 不带参数 = 交互模式；`cli` 带关键词 = 一次性扫描**。

### 交互模式（Memscan> 终端）

```bash
Memscan.exe cli          # 或直接双击 Memscan_CLI.exe
```

```
Memscan> 微信
Memscan> 微信 -a
Memscan> https -list -max 20
Memscan> exit
```

进入交互终端后：输入关键词直接扫描，扫完回到提示符可继续输入，`help` 查看说明，`exit` 退出。

### 一次性调用

```bash
Memscan.exe cli <关键词> [选项]
```

| 选项 | 说明 |
| --- | --- |
| `-a` | 全量扫描（全部编码） |
| `-case` | 区分大小写 |
| `-regex` | 正则匹配（仅 UTF-8） |
| `-net` | 仅显示有外联连接的进程 |
| `-list` | 紧凑列表模式（一行一个进程） |
| `-enc <列表>` | 指定搜索编码（默认 utf8；all=全部） |
| `-max <N>` | 最多输出 N 条命中（-list 下为进程数） |
| `-h` | 显示使用说明 |

**示例**

```bash
Memscan.exe cli "weixin.qq.com"                 # 搜域名 IOC
Memscan.exe cli "微信" -a                        # 全编码搜中文
Memscan.exe cli "https" -list -max 20           # 只看进程列表
Memscan.exe cli "メール" -enc utf16le,shift-jis  # 定向编码
```

## 🔤 正则速查

| 输入 | 含义 |
| --- | --- |
| `weixin\.qq\.com` | 精确匹配域名（点需转义） |
| `微信.*聊天记录` | 微信开头、聊天记录结尾，中间任意内容 |
| `(baidu\|qq)\.com` | 匹配 baidu.com 或 qq.com |
| `[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}` | IPv4 形态地址 |
| `abc+` | ab + 至少一个 c |

完整语法参考 [Go regexp/syntax](https://pkg.go.dev/regexp/syntax)。注意：正则模式仅按 UTF-8 搜索。

## 🖼️ 软件截图

<!-- 将截图放入 screenshots/ 目录后，把下面两行取消注释即可展示：
![主界面](screenshots/gui.png)
![命令行交互](screenshots/cli.png)
-->

> 待补充：建议放一张主界面（扫描结果 + 分页展开）和一张命令行交互（`Memscan>` 提示符）的截图。

## 🔨 编译

需要 Go 1.20.x（最后一个支持 Windows 7 / 8 / Server 2008 / Server 2012 的版本；仅 Win10/11 使用则更高版本亦可）。

```bash
# GUI 版（无控制台黑框）
go build -ldflags "-H windowsgui -s -w" -o Memscan.exe .

# CLI 版（带控制台）
go build -ldflags "-s -w" -o Memscan_CLI.exe .
```

图标资源 `rsrc_windows_amd64.syso` 已包含在仓库中（由 `rsrc.exe -ico ico.png -arch amd64 -o rsrc_windows_amd64.syso` 生成），直接 `go build` 即可自动带上图标。

## 📂 项目结构

```text
Memscan/
├── main.go                  # 全部源码（GUI + CLI 双模式）
├── bundled.go               # 打包的图标资源
├── ico.png                  # 应用图标
├── rsrc_windows_amd64.syso  # Windows 图标资源（go build 自动链接）
├── go.mod / go.sum
└── README.md
```

## 📋 已知限制

- `<!>` 标记仅表示“该进程当前有外联连接”，不代表连接的就是所搜 IOC，命中后请用 TCPView 等工具核实
- 每进程最多存储 200 条命中用于分页（真实命中数完整统计，超出时界面会提示“仅展示前 200 条”）
- 仅扫描 RW / RWX 内存区域，单区域超过 500MB 会跳过；建议以**管理员权限**运行以覆盖更多进程
- 外联地址为扫描瞬间的 TCP 连接快照，可能包含已断开连接（CLOSE_WAIT 等）与本机回环（127.0.0.1 代理 / 进程间通信）
- Windows Server 2008 等老系统若未安装任何中文字体，界面仍可能无法显示中文（中文版系统自带宋体 / 黑体即可）

## 🤝 参与贡献

- 欢迎提交 Issue 反馈问题、提出功能建议
- 欢迎 Fork 仓库进行二次开发，提交 PR 合并到主分支
- 如果觉得工具好用，欢迎 Star ⭐ 支持！

## ⚠️ 免责声明

本工具仅用于合法的应急响应、安全测试与恶意软件分析场景。

- 使用本工具需严格遵守《中华人民共和国网络安全法》及相关法律法规
- 禁止用于任何未授权的攻击、入侵或破坏行为
- 作者不对因滥用本工具造成的任何直接或间接损失承担责任
