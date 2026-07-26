# OAuth2 邮箱批量管理器

支持 Outlook/Hotmail/Gmail 等 OAuth2 IMAP 邮箱的批量管理工具。

## 功能

- **多供应商支持**：自动识别邮箱域名，配置对应的 IMAP/OAuth2 参数
  - Microsoft：outlook.com, hotmail.com, live.com, msn.com
  - Google：gmail.com
- **批量导入**：支持文本粘贴或文件上传，格式 `邮箱----密码----client_id----refresh_token`
- **OAuth2 IMAP 取件**：自动获取 access_token，支持 XOAUTH2 认证
- **令牌管理**：90 天有效期追踪，自动续期 + 手动更新
- **登录认证**：会话管理，默认 `admin` / `admin123`
- **Web 界面**：查看邮件详情、按文件夹筛选、分页浏览

## 部署

```bash
# 安装依赖
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 启动服务
python app.py
# 访问 http://0.0.0.0:8899
```

## systemd 服务

```bash
sudo cp outlook-mail-manager.service /etc/systemd/system/
sudo systemctl enable outlook-mail-manager
sudo systemctl start outlook-mail-manager
```

## 导入格式

```
邮箱----密码----client_id----refresh_token
```

- Microsoft 账号：`client_secret` 留空（密码字段存储账号密码备用）
- Gmail 账号：密码字段填写 `client_secret`（Google OAuth2 应用密钥）

## 配置

- 默认端口：`8899`
- 默认登录：`admin` / `admin123`
- 令牌有效期：90 天（可在 app.py 中修改 `TOKEN_LIFETIME_DAYS`）
