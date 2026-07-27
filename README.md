# OAuth2 邮箱批量管理器

支持 Outlook/Hotmail/Gmail 等 OAuth2 邮箱的批量管理工具。

## 功能

- **多供应商支持**：自动识别邮箱域名，配置对应的 IMAP/OAuth2 参数
  - Microsoft：outlook.com, hotmail.com, live.com, msn.com
  - Google：gmail.com
- **双取件模式（Microsoft）**：
  - **Graph API**（推荐）：应对近期 MS IMAP 风控，新导入 MS 账号默认启用
  - **IMAP (XOAUTH2)**：传统方式，可在账号设置页随时切换
  - ⚠️ Graph 模式要求 refresh_token 具有 `Mail.Read` scope；只有 IMAP scope 的旧 token 请切换回 IMAP 模式或换用新 token
- **中转代理**：全局 `OMM_PROXY` + 单账号代理（设置页可改，优先于全局），支持 socks5/socks5h/socks4/http，token 刷新与取件均走代理
- **批量导入**：文本粘贴或文件上传，格式 `邮箱----密码----client_id----refresh_token`
  - 重复导入同一邮箱仅更新凭据，账号状态与历史邮件完整保留
- **令牌管理**：90 天有效期追踪，取件时自动保存轮换后的新 token，14 天预警 + 手动更新
- **登录认证**：密码持久化（重启不丢），5 次失败锁定 5 分钟
- **Web 界面**：深色主题，邮件动态加载（无刷新翻页），按文件夹筛选，邮件去重入库

## 部署

```bash
# 安装依赖
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 启动服务
python app.py
# 访问 http://服务器IP:8899
```

默认登录：`admin` / `admin123`（首次登录后请立即在「修改密码」中更换，新密码持久化保存）。

## systemd 服务

```bash
sudo cp outlook-mail-manager.service /etc/systemd/system/
# 按需编辑其中的 WorkingDirectory / Environment
sudo systemctl enable outlook-mail-manager
sudo systemctl start outlook-mail-manager
```

## 环境变量

| 变量 | 说明 | 默认 |
|---|---|---|
| `OMM_ADMIN_PASSWORD` | 首次建库时的初始管理员密码 | `admin123` |
| `OMM_PROXY` | 全局中转代理，如 `socks5://user:pass@host:port` | 空（直连） |
| `OMM_MS_FETCH_MODE` | 新导入 MS 账号默认取件方式：`graph` / `imap` | `graph` |
| `OMM_PORT` | 监听端口 | `8899` |
| `OMM_DB_PATH` | 数据库文件路径 | 程序目录 `data.db` |

## 升级（保留数据）

代码变更均为增量迁移，**不会丢数据**：

```bash
cp data.db data.db.bak          # 建议先备份
git pull                        # 或上传新代码覆盖（不要覆盖 data.db）
pip install -r requirements.txt # 新增依赖：requests, PySocks
sudo systemctl restart outlook-mail-manager
```

启动时自动完成：新增 `fetch_mode`/`proxy` 列、清理孤儿邮件、去除重复邮件并建唯一索引、文件夹标签统一为 INBOX/JUNK。

## 导入格式

```
邮箱----密码----client_id----refresh_token
```

- Microsoft 账号：`client_secret` 留空（密码字段仅存档备用，取件不使用）
- Gmail 账号：密码字段填写 `client_secret`（Google OAuth2 应用密钥，导入时自动写入正确列）

## 测试

```bash
python smoke_test.py   # 内置冒烟测试：认证/改密/导入幂等/邮件去重/API鉴权/Graph 字段映射
```
