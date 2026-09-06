# Outlook Mail Manager

<p align="center">
  <img src="https://raw.githubusercontent.com/czppw/outlook-mail-manager/main/templates/base.html" alt="" width="0" height="0" />
  <strong>批量管理 Outlook / Hotmail / Gmail 邮箱 · OAuth2 免密取件 · 自动续期 Token </strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/FastAPI-Modern_UI-009688?logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Theme-Dark%20%26%20Light-6366F1" alt="Dual Theme" />
  <img src="https://img.shields.io/badge/Version-v1.3.0-blue" alt="Version" />
  <img src="https://img.shields.io/badge/Security-Fernet_Encrypted-success" alt="Security" />
</p>

---

面向 Outlook / Hotmail / Gmail 账号的现代化轻量级自托管管理面板。支持批量导入、Graph API REST / IMAP XOAUTH2 双模式高效取件、令牌时效健康监控、全局与单账号网络代理、邮件阅读清洗与安全沙盒隔离。

---

## ✨ v1.3.0 前端重构亮点

- 🎨 **Linear / Vercel 级设计美学**：彻底重构全套界面，告别简陋暗沉，采用科技感太空灰蓝与微光环境渐变。
- 🌓 **深色 (Dark) / 浅色 (Light) 双主题**：侧边栏一键自由切换，基于 CSS 变量自适应，首屏防闪烁，支持持久化记忆。
- 💡 **全新交互与组件**：
  - **内嵌毛玻璃模态框**：彻底替代原生粗糙的 `prompt()` / `confirm()`，删除确认、凭据导出密码二次验证体验丝滑。
  - **悬浮批量操作栏 (Floating Batch Bar)**：在表格中勾选多个账号时，底部自动升起毛玻璃工具栏，支持一键批量导出凭据。
  - **一键快捷复制**：表格邮箱旁配有即时复制按钮与气泡提示。
  - **呼吸指示灯与旋转加载器**：活跃账号呼吸微动效，取件、检测动作均配备平滑 Spinner。
  - **发件人色彩头像**：收件箱根据发件人首字母自动生成品牌色彩头像胶囊。
- 🛡️ **100% 离线自包含 & CSP 安全合规**：零第三方外部 CDN、零外部字体依赖，严格遵循后端极高强度的 Content Security Policy。

---

## 🚀 快速开始

本项目依赖 **Python 3.11** 或更高版本。

> [!IMPORTANT]
> **默认登录账号与密码**：
> - 登录地址：`http://127.0.0.1:8899`
> - 默认用户名：`admin`
> - 默认初始密码：`admin123`
> *(首次登录后建议立即在「全局设置」中修改访问密码)*

### 1. 克隆项目与安装依赖

```bash
git clone https://github.com/czppw/outlook-mail-manager.git
cd outlook-mail-manager
```

### 2. 启动服务

#### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements.lock

# 启动服务（默认监听 http://127.0.0.1:8899）
python app.py
```

#### Linux / macOS
```bash
python3 -m venv venv
source venv/bin/activate
pip install --require-hashes -r requirements.lock

# 启动服务（默认监听 http://127.0.0.1:8899）
python3 app.py
```

在浏览器中打开 **http://127.0.0.1:8899**，使用 `admin` / `admin123` 登录即可体验。

---

## 📦 核心功能特性

### 1. 双协议取件 (Graph API & IMAP)
- **Microsoft Graph API**（官方推荐）：采用微软最新的 REST API 读取邮件，完全免受传统 IMAP 端口的风控限制。
- **IMAP XOAUTH2**：支持经典 XOAUTH2 认证协议，完美兼容各类自建租户。
- **Gmail IMAP OAuth2**：支持 Google 邮箱的 OAuth2 授权收信。

### 2. 令牌自动续期与时效巡检
- **自动延期**：每次成功取件后，系统自动提取上游签发的新 Refresh Token 并加密落库。
- **时效监控看板**：实时诊断即将过期（默认 30 天内）与已过期的账号，支持一键向上游服务器验证令牌连通性。

### 3. 全局与独立代理
- 设置页支持配置全局中转代理（支持 `socks5` / `socks5h` / `socks4` / `http`），无需重启即时生效。
- 单独账号可指定专属代理节点，专属代理优先级高于全局代理。

### 4. 数据安全与隐私防护
- **敏感凭据高强度加密**：Refresh Token、密码与代理地址通过 Fernet 对称加密落盘存储。
- **邮件安全沙盒**：邮件正文经过 HTML 深度净化，采用隔离沙箱 `iframe` 渲染，阻断跟踪像素与恶意脚本执行。
- **防爆破与防跨站攻击**：内置 IP 登录限速（5 次错误自动锁定）、CSRF 校验与 Origin 来源防护。

---

## 📥 账号导入格式说明

支持在「导入账号」页面**直接粘贴**或**拖拽上传 TXT/CSV 文件**，每行一个账号，各字段以 `----`（四个减号）分隔：

```text
邮箱----密码/Secret----client_id----refresh_token
```

- **Microsoft 账号**：第二字段（密码）在 OAuth2 模式下可留空；需确保 Refresh Token 拥有 `Mail.Read` 或 `IMAP.AccessAsUser.All` 权限。
- **Gmail 账号**：第二字段填入 OAuth2 应用的 `client_secret`。
- **增量去重**：重复导入相同邮箱只会安全更新凭据，已抓取的历史邮件和账号 ID 均会完整保留。

---

## 🛡️ 生产环境部署 (Nginx + Systemd)

建议在 Linux 生产环境中通过 Systemd 托管，并通过 Nginx 配置 HTTPS 反向代理。

### 1. 创建服务配置

编辑 `/etc/systemd/system/outlook-mail-manager.service`：
```ini
[Unit]
Description=Outlook Mail Manager
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/outlook-mail-manager
Environment="OMM_HOST=127.0.0.1"
Environment="OMM_PORT=8899"
Environment="OMM_SECURE_COOKIE=1"
ExecStart=/opt/outlook-mail-manager/venv/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 2. Nginx 反向代理配置

```nginx
server {
    listen 443 ssl http2;
    server_name mail.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.yourdomain.com/privkey.pem;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:8899;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## ⚙️ 环境变量参考

| 变量名 | 类型 | 说明 | 默认值 |
|---|---|---|---|
| `OMM_HOST` | 字符串 | 绑定的监听地址 | `127.0.0.1` |
| `OMM_PORT` | 整数 | 监听端口 | `8899` |
| `OMM_ADMIN_PASSWORD` | 字符串 | 首次创建数据库时的初始密码 | `admin123` |
| `OMM_DB_PATH` | 路径 | SQLite 数据库存储路径 | `data.db` |
| `OMM_SECRET_KEY_FILE` | 路径 | Fernet 凭据加密密钥文件路径 | `.omm_secret.key` |
| `OMM_SECURE_COOKIE` | `0` / `1` | Cookie 是否强制 `Secure`（仅 HTTPS 传输） | 本地直连 `0` / 生产 `1` |
| `OMM_CHECK_ORIGIN` | `0` / `1` | 是否开启 Origin 来源校验（已适配回环地址） | `1` |
| `OMM_ALLOWED_ORIGINS` | 字符串 | 允许的反代来源白名单，以英文逗号分隔 | 空 |
| `OMM_FETCH_CONCURRENCY`| 整数 | 批量并发取件线程池容量（1-20） | `5` |
| `OMM_PROXY` | 字符串 | 默认全局中转代理地址 | 空 |

---

## 🧪 测试与质量验证

```bash
# 运行全部安全与功能单元测试
pytest

# 运行端到端离线冒烟测试
python smoke_test.py
```

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 开源。
