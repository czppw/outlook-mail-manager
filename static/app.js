(() => {
    "use strict";

    /* ============ CSRF & Core Requests ============ */

    const csrfToken = () => document.querySelector('meta[name="csrf-token"]')?.content || "";

    function toast(message, type = "") {
        let root = document.getElementById("toast-root");
        if (!root) {
            root = document.createElement("div");
            root.id = "toast-root";
            document.body.appendChild(root);
        }
        const item = document.createElement("div");
        item.className = `toast ${type}`;

        const icon = document.createElement("span");
        icon.innerHTML = type === "err"
            ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>'
            : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="9 12 11 14 15 10"/></svg>';
        
        const text = document.createElement("div");
        text.style.flex = "1";
        text.textContent = message;

        item.append(icon, text);
        root.appendChild(item);

        setTimeout(() => {
            item.style.opacity = "0";
            item.style.transform = "translateX(20px)";
            setTimeout(() => item.remove(), 200);
        }, 4500);
    }

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

    /* ============ Modern Modal Dialogs ============ */

    function showConfirmModal(title, message, isDanger = false) {
        return new Promise((resolve) => {
            const backdrop = document.createElement("div");
            backdrop.className = "modal-backdrop";

            const card = document.createElement("div");
            card.className = "modal-card";

            card.innerHTML = `
                <div class="modal-header">
                    <div class="modal-title">${escapeHtml(title)}</div>
                </div>
                <div class="modal-body">${escapeHtml(message)}</div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-cancel">取消</button>
                    <button type="button" class="btn ${isDanger ? 'btn-danger' : 'btn-primary'} btn-confirm">确认</button>
                </div>
            `;

            backdrop.appendChild(card);
            document.body.appendChild(backdrop);

            const cleanup = (result) => {
                backdrop.remove();
                resolve(result);
            };

            card.querySelector(".btn-cancel").addEventListener("click", () => cleanup(false));
            card.querySelector(".btn-confirm").addEventListener("click", () => cleanup(true));
            backdrop.addEventListener("click", (e) => {
                if (e.target === backdrop) cleanup(false);
            });
        });
    }

    function showPromptModal(title, message, placeholder = "", inputType = "text") {
        return new Promise((resolve) => {
            const backdrop = document.createElement("div");
            backdrop.className = "modal-backdrop";

            const card = document.createElement("div");
            card.className = "modal-card";

            card.innerHTML = `
                <div class="modal-header">
                    <div class="modal-title">${escapeHtml(title)}</div>
                </div>
                <div class="modal-body">
                    <p style="margin-bottom: 12px;">${escapeHtml(message)}</p>
                    <input type="${inputType}" class="modal-input" placeholder="${escapeHtml(placeholder)}" autofocus style="width: 100%;">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-cancel">取消</button>
                    <button type="button" class="btn btn-primary btn-confirm">确认</button>
                </div>
            `;

            backdrop.appendChild(card);
            document.body.appendChild(backdrop);

            const input = card.querySelector(".modal-input");
            input.focus();

            const cleanup = (val) => {
                backdrop.remove();
                resolve(val);
            };

            input.addEventListener("keydown", (e) => {
                if (e.key === "Enter") cleanup(input.value);
                if (e.key === "Escape") cleanup(null);
            });

            card.querySelector(".btn-cancel").addEventListener("click", () => cleanup(null));
            card.querySelector(".btn-confirm").addEventListener("click", () => cleanup(input.value));
            backdrop.addEventListener("click", (e) => {
                if (e.target === backdrop) cleanup(null);
            });
        });
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    /* ============ Theme Management ============ */

    function initTheme() {
        const saved = localStorage.getItem("omm_theme") || "dark";
        document.documentElement.dataset.theme = saved;
        updateThemeToggleBtn(saved);

        const btn = document.getElementById("theme-toggle");
        if (btn) {
            btn.addEventListener("click", () => {
                const current = document.documentElement.dataset.theme || "dark";
                const next = current === "dark" ? "light" : "dark";
                document.documentElement.dataset.theme = next;
                localStorage.setItem("omm_theme", next);
                updateThemeToggleBtn(next);
            });
        }
    }

    function updateThemeToggleBtn(theme) {
        const btn = document.getElementById("theme-toggle");
        if (!btn) return;
        const iconSpan = btn.querySelector(".theme-icon");
        const textSpan = btn.querySelector(".theme-text");
        if (theme === "light") {
            if (iconSpan) iconSpan.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>';
            if (textSpan) textSpan.textContent = "深色模式";
        } else {
            if (iconSpan) iconSpan.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>';
            if (textSpan) textSpan.textContent = "浅色模式";
        }
    }

    /* ============ Clipboard Helper ============ */

    function initCopyButtons() {
        document.querySelectorAll(".js-copy").forEach((btn) => {
            btn.addEventListener("click", async (e) => {
                e.stopPropagation();
                e.preventDefault();
                const text = btn.dataset.copyText;
                if (!text) return;
                try {
                    await navigator.clipboard.writeText(text);
                    const origTitle = btn.getAttribute("title") || "";
                    btn.setAttribute("title", "已复制！");
                    toast(`已复制: ${text}`, "ok");
                    setTimeout(() => btn.setAttribute("title", origTitle), 2000);
                } catch {
                    toast("复制失败，请手动选择复制", "err");
                }
            });
        });
    }

    /* ============ Account Fetching & Actions ============ */

    async function fetchAccount(button) {
        const id = button.dataset.accountId;
        button.disabled = true;
        const origContent = button.innerHTML;
        button.innerHTML = '<span class="spinner"></span> 取件中...';
        try {
            const data = await request(`/fetch/${id}`, {method: "POST"});
            if (data.partial) {
                toast(`取件部分完成：已保存 ${data.fetched} 封邮件；${data.error}`, "err");
            } else {
                toast(data.fetched > 0
                    ? `取件完成：新增 ${data.fetched} 封邮件`
                    : "取件完成：没有新邮件", "ok");
            }
            setTimeout(() => location.reload(), 800);
        } catch (error) {
            toast(`取件失败：${error.message}`, "err");
            button.disabled = false;
            button.innerHTML = origContent;
        }
    }

    async function fetchAll(button, healthCheck = false) {
        button.disabled = true;
        const origContent = button.innerHTML;
        button.innerHTML = `<span class="spinner"></span> ${healthCheck ? "检测中..." : "批量取件中..."}`;
        try {
            const data = await request(healthCheck ? "/check-all" : "/fetch-all", {method: "POST"});
            toast(healthCheck
                ? `健康检测完成\n可用: ${data.success} 个，异常: ${data.failed} 个`
                : `批量取件完成\n成功: ${data.success} 个，失败: ${data.failed} 个，新增: ${data.total_emails} 封`,
                data.failed > 0 ? "err" : "ok");
            setTimeout(() => location.reload(), 1200);
        } catch (error) {
            toast(`${healthCheck ? "检测" : "批量取件"}失败：${error.message}`, "err");
            button.disabled = false;
            button.innerHTML = origContent;
        }
    }

    async function setFetchMode(select) {
        const form = new FormData();
        form.append("fetch_mode", select.value);
        form.append("csrf_token", csrfToken());
        try {
            await request(`/account/${select.dataset.accountId}/prefs`, {method: "POST", body: form});
            select.dataset.previous = select.value;
            toast(`取件方式已切换为 ${select.value.toUpperCase()}`, "ok");
        } catch (error) {
            toast(`切换失败：${error.message}`, "err");
            select.value = select.dataset.previous;
        }
    }

    async function submitExport(ids) {
        if (!ids.length) {
            toast("请先选择账号", "err");
            return;
        }
        const password = await showPromptModal("安全验证", "请输入管理员密码以导出账号（含凭据明文）：", "管理员密码", "password");
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

    async function submitDeleteSelected(ids) {
        if (!ids.length) {
            toast("请先勾选要删除的账号", "err");
            return;
        }
        const confirmed = await showConfirmModal(
            "删除选中账号",
            `确定删除选中的 ${ids.length} 个账号及其全部历史邮件？此操作不可恢复。`,
            true
        );
        if (!confirmed) return;

        const form = document.createElement("form");
        form.method = "post";
        form.action = "/accounts/delete";
        form.hidden = true;
        const fields = [
            ["csrf_token", csrfToken()],
            ["next", `${location.pathname}${location.search}`],
        ];
        for (const id of ids) fields.push(["account_id", id]);
        for (const [name, value] of fields) {
            const input = document.createElement("input");
            input.name = name;
            input.value = value;
            form.appendChild(input);
        }
        document.body.appendChild(form);
        form.submit();
    }

    /* ============ Batch Action Bar ============ */

    function initBatchBar() {
        const selectAll = document.getElementById("select-all");
        const checkboxes = () => document.querySelectorAll(".account-check");
        let bar = document.getElementById("batch-bar");

        if (!bar && document.querySelector(".table-wrap")) {
            bar = document.createElement("div");
            bar.id = "batch-bar";
            bar.className = "batch-bar";
            bar.innerHTML = `
                <div class="batch-bar-count">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                    <span>已选 <strong id="batch-selected-count">0</strong> 个账号</span>
                </div>
                <div class="batch-bar-actions">
                    <button type="button" class="btn btn-sm btn-primary" id="batch-export-btn">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>
                        导出选中
                    </button>
                    <button type="button" class="btn btn-sm btn-danger" id="batch-delete-btn">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        删除选中
                    </button>
                    <button type="button" class="btn btn-sm" id="batch-cancel-btn">取消选择</button>
                </div>
            `;
            document.body.appendChild(bar);

            document.getElementById("batch-export-btn")?.addEventListener("click", () => {
                const ids = [...document.querySelectorAll(".account-check:checked")].map(b => b.value);
                submitExport(ids);
            });

            document.getElementById("batch-delete-btn")?.addEventListener("click", () => {
                const ids = [...document.querySelectorAll(".account-check:checked")].map(b => b.value);
                submitDeleteSelected(ids);
            });

            document.getElementById("batch-cancel-btn")?.addEventListener("click", () => {
                checkboxes().forEach(b => b.checked = false);
                if (selectAll) selectAll.checked = false;
                updateBatchBar();
            });
        }

        function updateBatchBar() {
            const checked = document.querySelectorAll(".account-check:checked");
            const countElem = document.getElementById("batch-selected-count");
            if (bar && countElem) {
                countElem.textContent = checked.length;
                if (checked.length > 0) {
                    bar.classList.add("visible");
                } else {
                    bar.classList.remove("visible");
                }
            }
        }

        if (selectAll) {
            selectAll.addEventListener("change", (e) => {
                checkboxes().forEach(box => box.checked = e.target.checked);
                updateBatchBar();
            });
        }

        document.addEventListener("change", (e) => {
            if (e.target.classList.contains("account-check")) {
                updateBatchBar();
                if (selectAll && !e.target.checked) {
                    selectAll.checked = false;
                }
            }
        });
    }

    /* ============ Inbox Infinite Scroll & Loader ============ */

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
            button.innerHTML = '<span class="spinner"></span> 加载中...';
            try {
                const data = await request(`/api/account/${accountId}/emails?folder=${encodeURIComponent(folder)}&page=${page + 1}`);
                const tbody = document.getElementById("mail-tbody");
                document.getElementById("empty-row")?.remove();

                for (const message of data.emails) {
                    const row = document.createElement("tr");

                    const from = document.createElement("td");
                    from.style.maxWidth = "260px";
                    from.style.overflow = "hidden";
                    from.style.textOverflow = "ellipsis";
                    from.style.whiteSpace = "nowrap";

                    const initial = (message.from || "?")[0].toUpperCase();
                    from.innerHTML = `<span class="sender-avatar">${escapeHtml(initial)}</span> ${escapeHtml((message.from || "").slice(0, 50))}`;

                    const subject = document.createElement("td");
                    const link = document.createElement("a");
                    link.href = `/email/${message.id}`;
                    link.textContent = (message.subject || "").slice(0, 80) || "(无主题)";
                    subject.appendChild(link);

                    const date = document.createElement("td");
                    date.style.color = "var(--text-muted)";
                    date.style.whiteSpace = "nowrap";
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
                toast(`加载失败：${error.message}`, "err");
            }
            button.disabled = false;
            button.innerHTML = '加载更多 ↓';
        });
    }

    /* ============ Update Manager Widget ============ */

    let updateBusy = false;

    async function checkForUpdate(fresh = false) {
        const widget = document.getElementById("version-widget");
        if (!widget || updateBusy) return;
        const status = widget.querySelector(".version-status");
        const button = widget.querySelector(".version-update");
        updateBusy = true;
        try {
            const data = await request(`/api/update/status${fresh ? "?fresh=1" : ""}`);
            widget.classList.remove("failed");
            if (!data.update_available) {
                widget.classList.add("is-current");
                if (status) status.textContent = "已是最新版本";
                return;
            }
            widget.classList.add("has-update");
            if (status) status.textContent = `发现新版本 v${data.latest_version}`;
            if (button) {
                button.hidden = false;
                button.dataset.version = data.latest_version;
            }
        } catch (error) {
            widget.classList.add("failed");
            if (status) status.textContent = "检查失败 · 点击重试";
            widget.title = error.message;
        } finally {
            updateBusy = false;
        }
    }

    async function applyUpdate(button) {
        const confirmed = await showConfirmModal(
            "版本更新",
            `确定安装新版本 v${button.dataset.version} 并重启服务吗？`
        );
        if (!confirmed) return;

        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span> 更新中...';
        try {
            await request("/api/update/apply", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({version: button.dataset.version}),
            });
            button.textContent = "正在重启...";
            toast("更新已安装，服务正在重启，页面将在几秒后刷新...", "ok");
            setTimeout(() => location.reload(), 5000);
        } catch (error) {
            toast(`更新失败：${error.message}`, "err");
            button.disabled = false;
            button.textContent = "⬆ 安装新版本";
        }
    }

    /* ============ Drag & Drop File Upload ============ */

    function initDropzone() {
        const dropzone = document.querySelector(".upload-dropzone");
        if (!dropzone) return;
        const fileInput = dropzone.querySelector('input[type="file"]');
        const title = dropzone.querySelector(".upload-title");

        dropzone.addEventListener("click", () => fileInput.click());

        fileInput.addEventListener("change", () => {
            if (fileInput.files.length) {
                title.textContent = `已选择: ${fileInput.files[0].name}`;
            }
        });

        ["dragenter", "dragover"].forEach(evt => {
            dropzone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropzone.classList.add("dragover");
            });
        });

        ["dragleave", "drop"].forEach(evt => {
            dropzone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropzone.classList.remove("dragover");
            });
        });

        dropzone.addEventListener("drop", (e) => {
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                title.textContent = `已选择: ${e.dataTransfer.files[0].name}`;
            }
        });
    }

    /* ============ Initialize ============ */

    document.addEventListener("DOMContentLoaded", () => {
        initTheme();
        initCopyButtons();
        initBatchBar();
        initDropzone();
        initInbox();

        // Button handlers
        document.querySelectorAll(".js-fetch-account").forEach((button) =>
            button.addEventListener("click", () => fetchAccount(button)));
        
        document.getElementById("fetch-all-btn")?.addEventListener("click", (e) =>
            fetchAll(e.currentTarget));
        
        document.getElementById("check-all-btn")?.addEventListener("click", (e) =>
            fetchAll(e.currentTarget, true));
        
        document.querySelectorAll(".js-fetch-mode").forEach((select) =>
            select.addEventListener("change", () => setFetchMode(select)));
        
        document.querySelectorAll(".js-auto-submit").forEach((select) =>
            select.addEventListener("change", () => select.form.submit()));

        // Modern confirm interceptor
        document.querySelectorAll("form[data-confirm]").forEach((form) => {
            form.addEventListener("submit", async (event) => {
                event.preventDefault();
                const confirmed = await showConfirmModal(
                    "确认操作",
                    form.dataset.confirm,
                    form.querySelector(".btn-danger") !== null
                );
                if (confirmed) {
                    form.removeAttribute("data-confirm");
                    form.submit();
                }
            });
        });

        // Export selected & export all
        document.getElementById("export-selected")?.addEventListener("click", () => {
            const ids = [...document.querySelectorAll(".account-check:checked")].map((box) => box.value);
            submitExport(ids);
        });

        document.getElementById("delete-selected")?.addEventListener("click", () => {
            const ids = [...document.querySelectorAll(".account-check:checked")].map((box) => box.value);
            submitDeleteSelected(ids);
        });

        document.getElementById("export-all")?.addEventListener("click", () => {
            submitExport(["all"]);
        });

        // Update widget
        document.getElementById("version-widget")?.addEventListener("click", () => checkForUpdate(true));
        document.querySelector(".version-update")?.addEventListener("click", (event) => {
            event.stopPropagation();
            applyUpdate(event.currentTarget);
        });

        checkForUpdate();
    });
})();
