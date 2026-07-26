# Outlook 邮箱批量管理器

批量管理 Outlook 邮箱账号，支持 OAuth2 IMAP 取件，自动续期 Token。

## 功能

- 📥 **批量导入账号** — 支持文本粘贴和文件上传，格式 `邮箱----密码----client_id----refresh_token`
- 📬 **OAuth2 IMAP 取件** — 自动获取收件箱和垃圾邮件
- 🔄 **Token 自动续期** — 每次取件自动保存微软返回的新 refresh_token，只要定期取件就不会过期
- ⏰ **过期提醒** — 到期前 14 天提醒，支持手动更新令牌
- 🔐 **登录认证** — Web 界面登录保护
- 🌙 **深色主题** — 简洁美观的 Web 界面

## 快速开始

```bash
# 克隆项目
git clone https://github.com/czppw/outlook-mail-manager.git
cd outlook-mail-manager

# 创建虚拟环境并安装依赖
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 启动
python app.py
```

访问 http://localhost:8899

**默认账号：** `admin` / `admin123`（请登录后立即修改密码）

## 账号格式

```
邮箱----密码----client_id----refresh_token
```

每行一个账号，支持 `#` 注释行。

## Token 续期机制

微软的 refresh_token 有效期约 90 天。系统有三层保护：

1. **自动续期** — 每次成功取件后，系统自动保存微软返回的新 token，重置 90 天计时器
2. **到期提醒** — Token 到期前 14 天，首页显示警告
3. **手动更新** — 如果 token 已过期，可以从卖家获取新 token，点击「更新令牌」替换

**只要定期取件（建议每周一次），token 就不会过期。**

## Systemd 部署

```bash
# 创建 service 文件
sudo tee /etc/systemd/system/outlook-mail-manager.service << 'EOF'
[Unit]
Description=Outlook Mail Manager
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/outlook-mail-manager
ExecStart=/home/ubuntu/outlook-mail-manager/venv/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable outlook-mail-manager
sudo systemctl start outlook-mail-manager
```

## 技术栈

- Python 3.11+
- FastAPI + Uvicorn
- SQLite (aiosqlite)
- Jinja2 模板
- OAuth2 XOAUTH2 (IMAP)

## License

MIT
