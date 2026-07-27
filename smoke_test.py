#!/usr/bin/env python3
"""
冒烟测试：不依赖真实邮箱 token，验证核心逻辑。

覆盖：
1. Graph 取件字段映射（mock requests，无需网络）
2. DB 层：导入/重复导入幂等、Gmail client_secret 映射、邮件去重、改密
3. HTTP 端到端：认证跳转、API 401、登录/改密/重启后密码持久化、导入、登录限速

用法：python smoke_test.py
"""
import asyncio
import importlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time

import requests

REPO = os.path.dirname(os.path.abspath(__file__))
BASE = "http://127.0.0.1:18899"

_fails = []


def check(name, cond, detail=""):
    tag = "PASS" if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" - {detail}" if detail and not cond else ""))
    if not cond:
        _fails.append(name)


# ─────────── Part 1: Graph 字段映射（mock）───────────

def test_graph_mapping():
    print("\n== Part 1: Graph 字段映射 ==")
    import mail_fetcher

    class FakeResp:
        def __init__(self, payload, status=200):
            self._p = payload
            self.status_code = status
            self.text = json.dumps(payload)

        def json(self):
            return self._p

    calls = {}

    def fake_post(url, data=None, timeout=None, proxies=None):
        calls["token_data"] = data
        return FakeResp({"access_token": "AT", "refresh_token": "NEW_RT"})

    def fake_get(url, headers=None, params=None, timeout=None, proxies=None):
        calls["auth"] = headers.get("Authorization")
        return FakeResp({"value": [{
            "id": "msg1",
            "subject": "Hello",
            "from": {"emailAddress": {"name": "Alice", "address": "a@x.com"}},
            "receivedDateTime": "2026-07-27T01:00:00Z",
            "body": {"contentType": "html", "content": "<b>hi</b>"},
        }]})

    orig_post, orig_get = mail_fetcher.requests.post, mail_fetcher.requests.get
    mail_fetcher.requests.post, mail_fetcher.requests.get = fake_post, fake_get
    try:
        results, new_rt = mail_fetcher._fetch_via_graph("u@outlook.com", "cid", "RT", "", "", 10)
    finally:
        mail_fetcher.requests.post, mail_fetcher.requests.get = orig_post, orig_get

    check("Graph 返回轮换后的 refresh_token", new_rt == "NEW_RT")
    check("Graph 刷新请求带 Mail.Read scope", "Mail.Read" in calls["token_data"]["scope"])
    check("Graph Authorization 头正确", calls["auth"] == "Bearer AT")
    check("Graph 拉取 INBOX+JUNK 两个文件夹", set(results.keys()) == {"INBOX", "JUNK"})
    em = results["INBOX"][0]
    check("Graph 字段映射(uid/subject/from/html)",
          em["uid"] == "msg1" and em["subject"] == "Hello"
          and "Alice" in em["from"] and em["body_html"] == "<b>hi</b>")


# ─────────── Part 2: DB 层 ───────────

def test_db_layer(tmpdir):
    print("\n== Part 2: DB 层 ==")
    os.environ["OMM_DB_PATH"] = os.path.join(tmpdir, "t1.db")
    import db
    importlib.reload(db)

    async def main():
        await db.init_db()
        r1 = await db.import_accounts([
            "a@outlook.com----p1----cid1----rt1",
            "g@gmail.com----secret2----cid2----rt2",
        ])
        check("首次导入 added=2", r1["added"] == 2 and r1["failed"] == 0, str(r1))

        accs, _ = await db.get_accounts()
        gmail = next(a for a in accs if a["provider"] == "google")
        check("Gmail client_secret 写入正确列", gmail["client_secret"] == "secret2")
        ms = next(a for a in accs if a["provider"] == "microsoft")
        check("MS 账号默认 Graph 模式", ms["fetch_mode"] == "graph")

        aid = ms["id"]
        await db.update_account_status(aid, "active", mail_count=7)
        n = await db.save_emails(aid, "INBOX", [
            {"uid": "1", "from": "x", "subject": "s", "body": "", "body_html": "", "date": ""}
        ])
        check("邮件首次入库", n == 1)

        r2 = await db.import_accounts(["a@outlook.com----p1n----cid1----rt1new"])
        check("重复导入计为 updated", r2["updated"] == 1 and r2["added"] == 0, str(r2))
        acc = await db.get_account(aid)
        check("重复导入保留 id/状态/邮件数",
              acc["id"] == aid and acc["status"] == "active" and acc["mail_count"] == 7)
        check("重复导入 token 已更新", acc["refresh_token"] == "rt1new")
        check("重复导入后历史邮件仍在", await db.get_email_count(aid) == 1)

        n1 = await db.save_emails(aid, "INBOX", [
            {"uid": "1", "from": "x", "subject": "s", "body": "", "body_html": "", "date": ""}
        ])
        check("重复邮件去重(同uid)", n1 == 0)
        n2 = await db.save_emails(aid, "INBOX", [
            {"uid": "2", "from": "y", "subject": "s2", "body": "", "body_html": "", "date": ""}
        ])
        check("新邮件正常入库", n2 == 1)

        check("改密成功(正确旧密码)", await db.change_password("admin123", "newpass99"))
        check("改密拒绝(错误旧密码)", not await db.change_password("wrong-old", "whatever1"))
        check("新密码可登录", await db.verify_user("admin", "newpass99"))
        check("旧密码已失效", not await db.verify_user("admin", "admin123"))

    asyncio.run(main())


# ─────────── Part 2b: 旧版库结构迁移 ───────────

def test_legacy_schema(tmpdir):
    """某些部署版本用 last_error/sender/received_at 列名，init_db 应自动重命名兼容。"""
    print("\n== Part 2b: 旧版库结构迁移 ==")
    path = os.path.join(tmpdir, "legacy.db")
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
            password TEXT, client_id TEXT, refresh_token TEXT, status TEXT DEFAULT 'pending',
            last_check TEXT, last_error TEXT, mail_count INTEGER DEFAULT 0,
            created_at TEXT, token_created_at TEXT);
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL,
            uid TEXT NOT NULL, folder TEXT DEFAULT 'INBOX', sender TEXT, subject TEXT,
            body TEXT, body_html TEXT, received_at TEXT, is_read INTEGER DEFAULT 0,
            fetched_at TEXT);
        INSERT INTO accounts (email, password, client_id, refresh_token)
        VALUES ('old@outlook.com', 'p', 'c', 'r');
    """)
    con.close()

    os.environ["OMM_DB_PATH"] = path
    import db
    importlib.reload(db)
    asyncio.run(db.init_db())

    con = sqlite3.connect(path)
    acc_cols = {r[1] for r in con.execute("PRAGMA table_info(accounts)")}
    em_cols = {r[1] for r in con.execute("PRAGMA table_info(emails)")}
    check("last_error 重命名为 error", "error" in acc_cols and "last_error" not in acc_cols)
    check("sender 重命名为 from_addr", "from_addr" in em_cols and "sender" not in em_cols)
    check("received_at 重命名为 date", "date" in em_cols and "received_at" not in em_cols)
    check("旧账号数据保留", con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1)
    con.close()

    n = asyncio.run(db.save_emails(1, "INBOX", [
        {"uid": "u1", "from": "a", "subject": "s", "body": "", "body_html": "", "date": ""}
    ]))
    check("迁移后邮件可正常入库", n == 1)


# ─────────── Part 3: HTTP 端到端 ───────────

def _start_server(env):
    proc = subprocess.Popen(
        [sys.executable, "app.py"], cwd=REPO, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        try:
            if requests.get(BASE + "/login", timeout=1).status_code == 200:
                return proc
        except requests.RequestException:
            time.sleep(0.3)
    proc.terminate()
    raise RuntimeError("服务启动失败")


def test_http(tmpdir):
    print("\n== Part 3: HTTP 端到端 ==")
    db2 = os.path.join(tmpdir, "t2.db")
    env = dict(os.environ, OMM_DB_PATH=db2, OMM_PORT="18899", OMM_MS_FETCH_MODE="imap")

    proc = _start_server(env)
    try:
        s = requests.Session()
        r = s.get(BASE + "/", allow_redirects=False)
        check("未认证访问首页跳转登录", r.status_code == 302 and "/login" in r.headers.get("Location", ""))
        r = s.get(BASE + "/api/stats", allow_redirects=False)
        check("/api/stats 未认证返回 401", r.status_code == 401)
        r = s.get(BASE + "/api/account/1/emails", allow_redirects=False)
        check("邮件 API 未认证返回 401", r.status_code == 401)

        r = s.post(BASE + "/login", data={"username": "admin", "password": "bad"}, allow_redirects=False)
        check("错误密码登录被拒", "用户名或密码错误" in r.text)
        r = s.post(BASE + "/login", data={"username": "admin", "password": "admin123"}, allow_redirects=False)
        check("正确密码登录成功", r.status_code == 302)
        r = s.get(BASE + "/")
        check("首页可访问", r.status_code == 200 and "账号列表" in r.text)

        r = s.post(BASE + "/import", data={"text": "t1@outlook.com----p----cid----rt\nt2@gmail.com----sec----cid----rt2"})
        check("HTTP 导入新增 2 个", "新增 <strong>2</strong>" in r.text)
        r = s.post(BASE + "/import", data={"text": "t1@outlook.com----p----cid----rt\nt2@gmail.com----sec----cid----rt2"})
        check("HTTP 重复导入更新 2 个", "更新 <strong>2</strong>" in r.text)
        r = s.get(BASE + "/")
        check("OMM_MS_FETCH_MODE=imap 导入默认生效", 'data-prev="imap"' in r.text)

        r = s.post(BASE + "/password", data={"old_password": "admin123", "new_password": "testpass456"})
        check("界面改密成功", "密码已修改" in r.text)
        r = s.post(BASE + "/password", data={"old_password": "admin123", "new_password": "testpass456"})
        check("旧密码改密被拒", "旧密码错误" in r.text)
        s.get(BASE + "/logout")
        r = s.post(BASE + "/login", data={"username": "admin", "password": "admin123"}, allow_redirects=False)
        check("改密后旧密码失效", "用户名或密码错误" in r.text)
        r = s.post(BASE + "/login", data={"username": "admin", "password": "testpass456"}, allow_redirects=False)
        check("改密后新密码可登录", r.status_code == 302)

        r = s.get(BASE + "/api/account/1/emails")
        check("邮件 API 认证后可用", r.status_code == 200 and "emails" in r.json())

        # 全局设置页
        r = s.get(BASE + "/settings")
        check("设置页可访问", r.status_code == 200 and "全局设置" in r.text)
        r = s.post(BASE + "/settings", data={"global_proxy": "socks5://127.0.0.1:1080",
                                             "default_ms_fetch_mode": "imap"})
        check("设置保存成功", "设置已保存" in r.text)
        r = s.get(BASE + "/settings")
        check("设置已持久化", "socks5://127.0.0.1:1080" in r.text)
        s.post(BASE + "/settings", data={"global_proxy": "", "default_ms_fetch_mode": "graph"})

        # 导出账号
        r = s.get(BASE + "/export")
        check("导出包含账号且为导入格式",
              r.status_code == 200 and "t1@outlook.com----p----cid----rt" in r.text)
        r = requests.get(BASE + "/export", allow_redirects=False)
        check("导出未认证跳转登录", r.status_code == 302)

        # 列表下拉切换取件方式
        r = s.post(BASE + "/account/1/prefs", data={"fetch_mode": "graph"})
        check("下拉切换 Graph 成功", r.status_code == 200 and r.json().get("fetch_mode") == "graph")
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 重启：验证密码持久化 + 登录限速
    proc = _start_server(env)
    try:
        r = requests.post(BASE + "/login", data={"username": "admin", "password": "testpass456"}, allow_redirects=False)
        check("重启后新密码仍有效(持久化)", r.status_code == 302)
        for _ in range(5):
            requests.post(BASE + "/login", data={"username": "admin", "password": "bad"})
        r = requests.post(BASE + "/login", data={"username": "admin", "password": "testpass456"})
        check("登录限速生效(5次失败锁定)", "尝试次数过多" in r.text)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    con = sqlite3.connect(db2)
    rows = con.execute("SELECT id, email, client_secret, fetch_mode FROM accounts ORDER BY id").fetchall()
    con.close()
    check("HTTP 导入 2 个账号", len(rows) == 2)
    check("下拉切换 fetch_mode 已落库", rows[0][3] == "graph")
    check("Gmail client_secret 经 HTTP 导入正确", rows[1][2] == "sec")


def main():
    tmpdir = tempfile.mkdtemp(prefix="omm_test_")
    print(f"测试目录: {tmpdir}")
    test_graph_mapping()
    test_db_layer(tmpdir)
    test_legacy_schema(tmpdir)
    test_http(tmpdir)
    print("\n" + ("=" * 40))
    if _fails:
        print(f"❌ {len(_fails)} 项失败: {_fails}")
        sys.exit(1)
    print("✅ 全部冒烟测试通过")


if __name__ == "__main__":
    main()
