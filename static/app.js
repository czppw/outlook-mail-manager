(() => {
    "use strict";

    const csrfToken = () => document.querySelector('meta[name="csrf-token"]')?.content || "";

    async function request(url, options = {}) {
        const headers = new Headers(options.headers || {});
        if ((options.method || "GET").toUpperCase() !== "GET") {
            headers.set("X-CSRF-Token", csrfToken());
        }
        const response = await fetch(url, {...options, headers});
        const contentType = response.headers.get("content-type") || "";
        const body = contentType.includes("application/json") ? await response.json() : null;
        if (!response.ok) {
            throw new Error(body?.error || body?.detail || `HTTP ${response.status}`);
        }
        return body;
    }

    async function fetchAccount(button) {
        const id = button.dataset.accountId;
        button.disabled = true;
        button.textContent = "取件中...";
        try {
            const data = await request(`/fetch/${id}`, {method: "POST"});
            if (data.partial) {
                alert(`取件部分完成：已保存 ${data.fetched} 封邮件；${data.error}`);
            } else {
                alert(data.fetched > 0
                    ? `取件完成：新增 ${data.fetched} 封邮件`
                    : "取件完成：没有新邮件");
            }
            location.reload();
        } catch (error) {
            alert(`取件失败：${error.message}`);
            button.disabled = false;
            button.textContent = "取件";
        }
    }

    async function fetchAll(button, healthCheck = false) {
        button.disabled = true;
        button.textContent = healthCheck ? "检测中..." : "批量取件中...";
        try {
            const data = await request(healthCheck ? "/check-all" : "/fetch-all", {method: "POST"});
            alert(healthCheck
                ? `健康检测完成\n可用: ${data.success} 个，异常: ${data.failed} 个`
                : `批量取件完成\n成功: ${data.success} 个，失败: ${data.failed} 个，新增: ${data.total_emails} 封`);
            location.reload();
        } catch (error) {
            alert(`${healthCheck ? "检测" : "批量取件"}失败：${error.message}`);
            button.disabled = false;
            button.textContent = healthCheck ? "一键检测" : "全部取件";
        }
    }

    async function setFetchMode(select) {
        const form = new FormData();
        form.append("fetch_mode", select.value);
        form.append("csrf_token", csrfToken());
        try {
            await request(`/account/${select.dataset.accountId}/prefs`, {method: "POST", body: form});
            select.dataset.previous = select.value;
        } catch (error) {
            alert(`切换失败：${error.message}`);
            select.value = select.dataset.previous;
        }
    }

    function submitExport(ids) {
        if (!ids.length) {
            alert("请先选择账号");
            return;
        }
        const password = prompt("请输入当前管理员密码");
        if (!password) return;
        const form = document.createElement("form");
        form.method = "post";
        form.action = "/export";
        form.hidden = true;
        const fields = [["csrf_token", csrfToken()], ["current_password", password]];
        for (const id of ids) fields.push(["account_id", id]);
        for (const [name, value] of fields) {
            const input = document.createElement("input");
            input.name = name;
            input.value = value;
            form.appendChild(input);
        }
        document.body.appendChild(form);
        form.submit();
        setTimeout(() => form.remove(), 1000);
    }

    function initInbox() {
        const state = document.getElementById("inbox-state");
        const button = document.getElementById("load-more-btn");
        if (!state || !button) return;
        let page = Number(state.dataset.page);
        let loaded = Number(state.dataset.loaded);
        const accountId = state.dataset.accountId;
        const folder = state.dataset.folder;
        button.addEventListener("click", async () => {
            button.disabled = true;
            button.textContent = "加载中...";
            try {
                const data = await request(`/api/account/${accountId}/emails?folder=${encodeURIComponent(folder)}&page=${page + 1}`);
                const tbody = document.getElementById("mail-tbody");
                document.getElementById("empty-row")?.remove();
                for (const message of data.emails) {
                    const row = document.createElement("tr");
                    const from = document.createElement("td");
                    from.textContent = (message.from || "").slice(0, 50);
                    const subject = document.createElement("td");
                    const link = document.createElement("a");
                    link.href = `/email/${message.id}`;
                    link.textContent = (message.subject || "").slice(0, 80) || "(无主题)";
                    subject.appendChild(link);
                    const date = document.createElement("td");
                    date.textContent = message.date || "-";
                    const folderCell = document.createElement("td");
                    const badge = document.createElement("span");
                    badge.className = "badge";
                    badge.textContent = message.folder;
                    folderCell.appendChild(badge);
                    row.append(from, subject, date, folderCell);
                    tbody.appendChild(row);
                }
                page = data.page;
                loaded += data.emails.length;
                document.getElementById("page-info").textContent = `已加载 ${loaded} / ${data.total} 封`;
                if (page >= data.total_pages) {
                    button.remove();
                    return;
                }
            } catch (error) {
                alert(`加载失败：${error.message}`);
            }
            button.disabled = false;
            button.textContent = "加载更多";
        });
    }

    async function checkForUpdate() {
        const widget = document.getElementById("version-widget");
        if (!widget) return;
        const status = widget.querySelector(".version-status");
        const button = widget.querySelector(".version-update");
        try {
            const data = await request("/api/update/status");
            if (!data.update_available) {
                widget.classList.add("is-current");
                status.textContent = "已是最新";
                return;
            }
            widget.classList.add("has-update");
            status.textContent = `可更新至 v${data.latest_version}`;
            button.hidden = false;
            button.dataset.version = data.latest_version;
        } catch (error) {
            status.textContent = "检查失败";
            widget.title = error.message;
        }
    }

    async function applyUpdate(button) {
        if (!confirm(`安装 v${button.dataset.version} 并重启服务？`)) return;
        button.disabled = true;
        button.textContent = "更新中...";
        try {
            await request("/api/update/apply", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({version: button.dataset.version}),
            });
            button.textContent = "正在重启...";
            setTimeout(() => location.reload(), 5000);
        } catch (error) {
            alert(`更新失败：${error.message}`);
            button.disabled = false;
            button.textContent = "更新";
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        document.querySelectorAll(".js-fetch-account").forEach((button) =>
            button.addEventListener("click", () => fetchAccount(button)));
        document.getElementById("fetch-all-btn")?.addEventListener("click", (event) => fetchAll(event.currentTarget));
        document.getElementById("check-all-btn")?.addEventListener("click", (event) => fetchAll(event.currentTarget, true));
        document.querySelectorAll(".js-fetch-mode").forEach((select) =>
            select.addEventListener("change", () => setFetchMode(select)));
        document.querySelectorAll(".js-auto-submit").forEach((select) =>
            select.addEventListener("change", () => select.form.submit()));
        document.querySelectorAll("form[data-confirm]").forEach((form) =>
            form.addEventListener("submit", (event) => {
                if (!confirm(form.dataset.confirm)) event.preventDefault();
            }));
        document.getElementById("select-all")?.addEventListener("change", (event) => {
            document.querySelectorAll(".account-check").forEach((box) => { box.checked = event.currentTarget.checked; });
        });
        document.getElementById("export-selected")?.addEventListener("click", () => {
            const ids = [...document.querySelectorAll(".account-check:checked")].map((box) => box.value);
            submitExport(ids);
        });
        document.getElementById("export-all")?.addEventListener("click", () => {
            submitExport(["all"]);
        });
        document.querySelector(".version-update")?.addEventListener("click", (event) => applyUpdate(event.currentTarget));
        initInbox();
        checkForUpdate();
    });
})();
