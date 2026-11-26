(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const state = {
    user: null,
    classes: [],
    assignments: [],
    bootstrap: { classes: [], subjects: [] },
    drafts: new Map(),
    conflict: null,
    tourActive: false,
    tourOffered: false,
    admin: {
      view: "overview",
      returnView: "overview",
      usersPage: 1,
      usersQ: "",
      studentsPage: 1,
      studentsQ: "",
      auditPage: 1,
      auditQ: "",
      auditResult: "",
      auditKind: "score",
      analyticsNationalId: null,
      analyticsTopic: "",
      analyticsYear: "",
    },
  };

  const esc = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[character]);

  const fa = (value) => {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? new Intl.NumberFormat("fa-IR").format(numeric) : esc(value);
  };
  const faDate = (value) => {
    if (!value) return "—";
    try {
      return new Date(value).toLocaleString("fa-IR");
    } catch {
      return "—";
    }
  };
  const normalizeDigits = (value) =>
    String(value ?? "")
      .replace(/[۰-۹]/g, (digit) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(digit)))
      .replace(/[٠-٩]/g, (digit) => String("٠١٢٣٤٥٦٧٨٩".indexOf(digit)));
  const reportKey = (value) =>
    normalizeDigits(String(value || "کارنامه").trim().toLocaleLowerCase("fa-IR"))
      .replace(/[آأإ]/g, "ا")
      .replace(/ي/g, "ی")
      .replace(/ك/g, "ک")
      .replace(/[ۀة]/g, "ه")
      .replace(/[\u200c\s_\-.()]/g, "");

  let toastTimer = 0;
  function toast(message, type = "info", important = true) {
    const stack = $("#toast-stack");
    if (!stack) return;
    const item = document.createElement("div");
    item.className = `toast ${type}`;
    item.textContent = message;
    stack.appendChild(item);
    const remove = () => item.remove();
    setTimeout(remove, important ? 6500 : 4000);
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      while (stack.children.length > 4) stack.firstElementChild.remove();
    }, 200);
  }

  async function api(url, options = {}) {
    const response = await fetch(url, {
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
    });
    if (response.status === 204) return null;
    const data = await response.json().catch(() => ({ error: "پاسخ سرور خوانده نشد." }));
    if (!response.ok) {
      const error = new Error(data.error || "درخواست انجام نشد.");
      error.status = response.status;
      error.data = data;
      if (response.status === 401 && url !== "/api/me" && url !== "/api/login") {
        showAuth();
        toast("نشست شما منقضی شده است؛ دوباره وارد شوید.", "warning");
      }
      throw error;
    }
    return data;
  }

  function formError(form, message) {
    const box = form.querySelector(".form-error");
    if (box) box.textContent = message || "";
  }

  function classLabel(classId) {
    const found = state.bootstrap.classes.find((item) => item.id === classId) ||
      state.classes.find((item) => item.id === classId);
    if (!found) return classId || "—";
    return found.label || [found.grade, found.field, found.section].filter(Boolean).join(" · ") || found.id;
  }

  function showAuth() {
    $("#dashboard").hidden = true;
    $("#auth").hidden = false;
    state.user = null;
  }

  function showSecurityStep() {
    $("#security-step").hidden = false;
    $("#auth-step").hidden = true;
  }

  function showAuthCredentials() {
    $("#security-step").hidden = true;
    $("#auth-step").hidden = false;
  }

  function setTab(name) {
    $$(".tab[data-tab]").forEach((button) => {
      const active = button.dataset.tab === name;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
    });
    $("#login-form").hidden = name !== "login";
    $("#register-form").hidden = name !== "register";
  }

  function setAdminView(view) {
    const allowed = ["overview", "users", "students", "activity"];
    if (view !== "account" && !allowed.includes(view)) view = "overview";
    if (view !== "account") state.admin.returnView = view;
    state.admin.view = view;
    const account = view === "account";
    $("#admin-panel").hidden = account || state.user?.role !== "admin";
    $("#account-view").hidden = !account;
    $("#dashboard-grid").hidden = state.user?.role === "admin" ? !account : account;
    $$("[data-admin-view]").forEach((section) => {
      section.hidden = section.dataset.adminView !== view;
    });
    $$("[data-admin-tab]").forEach((button) => {
      const active = button.dataset.adminTab === view;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
      button.tabIndex = active ? 0 : -1;
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function defaultAcademicYear() {
    try {
      const year = new Intl.DateTimeFormat("en-u-ca-persian-nu-latn", { year: "numeric" }).format(new Date());
      return `${year}-${Number(year) + 1}`;
    } catch {
      return "";
    }
  }

  async function init() {
    $("#security-code").focus();
    try {
      const me = await api("/api/me");
      state.user = me.user;
      showDashboard();
      if (state.user.role === "admin") return;
      if (location.pathname === "/tour" || new URLSearchParams(location.search).has("tour")) {
        startTour();
      } else {
        offerTour();
      }
    } catch {
      showAuth();
      showSecurityStep();
    }
  }

  async function showDashboard() {
    if (state.user?.role === "admin") {
      $("#auth").hidden = true;
      $("#dashboard").hidden = true;
      $("#manager-desktop").hidden = false;
      return;
    }
    $("#manager-desktop").hidden = true;
    $("#auth").hidden = true;
    $("#dashboard").hidden = false;
    $("#welcome").textContent = `${state.user.firstName} ${state.user.lastName}`;
    $("#role-badge").textContent = state.user.role === "admin" ? "مدیر مدرسه" : "معلم";
    $("#profile-form").elements.firstName.value = state.user.firstName;
    $("#profile-form").elements.lastName.value = state.user.lastName;
    $("#profile-form").elements.nationalId.value = state.user.nationalId;
    $("#profile-form").elements.phone.value = state.user.phone;
    if (!$("#academic-year").value) $("#academic-year").value = defaultAcademicYear();
    const teacherVisible = state.user.role === "teacher" || (state.user.assignments || []).length > 0;
    $("#teacher-panel").hidden = !teacherVisible;
    $("#account-view").hidden = true;
    if (teacherVisible) {
      try {
        const data = await api("/api/teacher/classes");
        state.classes = data.classes || [];
        state.assignments = data.assignments || [];
        const select = $("#class-select");
        select.innerHTML =
          '<option value="">انتخاب کلاس</option>' +
          state.classes
            .map((item) => `<option value="${esc(item.id)}">${esc(classLabel(item.id))}</option>`)
            .join("");
        if (state.classes.length === 1) {
          select.value = state.classes[0].id;
          updateSubjects();
        }
      } catch (error) {
        toast(error.message, "error");
      }
    }
    if (state.user.role === "admin") {
      $("#dashboard-grid").hidden = true;
      $("#admin-panel").hidden = false;
      setAdminView("overview");
      await loadAdmin();
    } else {
      $("#dashboard-grid").hidden = false;
      $("#admin-panel").hidden = true;
    }
  }

  function updateSubjects() {
    const classId = $("#class-select").value;
    const list = [
      ...new Map(
        state.assignments
          .filter((item) => item.classId === classId)
          .map((item) => [item.subjectId, item]),
      ).values(),
    ];
    $("#subject-select").innerHTML =
      '<option value="">انتخاب درس</option>' +
      list.map((item) => `<option value="${esc(item.subjectId)}">${esc(item.subjectName)}</option>`).join("");
  }

  function assignmentFor(classId, subjectId) {
    return state.assignments.find(
      (item) => item.classId === classId && item.subjectId === subjectId,
    );
  }

  async function loadRoster() {
    const classId = $("#class-select").value;
    const subjectId = $("#subject-select").value;
    const academicYear = $("#academic-year").value.trim();
    const reportType = $("#report-topic").value.trim();
    if (!classId || !subjectId || !academicYear || !reportType) {
      toast("کلاس، درس، سال تحصیلی و موضوع آزمون را کامل انتخاب کنید.", "warning");
      return;
    }
    const assignment = assignmentFor(classId, subjectId);
    if (!assignment) {
      toast("این کلاس و درس در دسترسی حساب شما نیست.", "error");
      return;
    }
    state.drafts.clear();
    state.conflict = null;
    $("#teacher-conflict").hidden = true;
    $("#status").textContent = "";
    $("#roster").innerHTML = '<tr><td colspan="5" class="empty-row">در حال خواندن فهرست…</td></tr>';
    try {
      const query = new URLSearchParams({ classId, academicYear, reportType });
      const [roster, reports] = await Promise.all([
        api(`/api/teacher/roster?classId=${encodeURIComponent(classId)}&limit=200`),
        api(`/api/teacher/reports?${query.toString()}`),
      ]);
      state.students = roster.students || [];
      const reportMap = new Map((reports.reports || []).map((report) => [report.nationalId, report]));
      const rows = state.students.map((student, index) => {
        const existing = reportMap.get(student.nationalId);
        const draftId = existing?.id || `draft-${student.nationalId}-${classId}-${reportKey(reportType)}`;
        const record = existing
          ? { exists: true, report: { ...existing, scores: { ...(existing.scores || {}) } } }
          : {
              exists: false,
              report: {
                id: draftId,
                nationalId: student.nationalId,
                firstName: student.firstName,
                lastName: student.lastName,
                classId,
                academicYear,
                reportType,
                scores: {},
                subjectSnapshot: [],
                scoreActors: {},
                revision: 0,
              },
            };
        if (!record.report.scores) record.report.scores = {};
        state.drafts.set(draftId, record);
        const score = record.report.scores[subjectId];
        const value = score === undefined || score === null ? "" : String(score);
        const actor = record.report.scoreActors?.[subjectId]?.name;
        const statusText = actor
          ? `آخرین ثبت: ${actor}`
          : existing
            ? "درس در این کارنامه ثبت نشده"
            : "آمادهٔ ثبت";
        return `<tr data-record="${esc(draftId)}" data-student="${esc(student.nationalId)}" data-existing="${existing ? "1" : "0"}">
          <td>${fa(index + 1)}</td>
          <td><b>${esc(student.firstName)} ${esc(student.lastName)}</b><small class="block-note">${esc(student.nationalId)}</small></td>
          <td><input class="score-input" data-record="${esc(draftId)}" data-subject="${esc(subjectId)}" type="number" inputmode="decimal" min="-2" max="20" step="0.01" value="${esc(value)}" aria-label="نمره ${esc(student.firstName)} ${esc(student.lastName)}"></td>
          <td class="row-state">${esc(statusText)}</td>
          <td>${existing ? `<button class="text-button danger-text" type="button" data-delete-report="${esc(existing.id)}">حذف</button>` : ""}</td>
        </tr>`;
      });
      $("#roster").innerHTML =
        rows.join("") || '<tr><td colspan="5" class="empty-row">فهرست این کلاس خالی است.</td></tr>';
      $("#count").textContent = `${fa(state.students.length)} دانش‌آموز`;
      $("#save-scores").disabled = rows.length === 0 || state.tourActive;
      $("#save-state").textContent = "تغییری ثبت نشده";
      $("#status").textContent = `${assignment.subjectName} · ${academicYear} · ${reportType}`;
    } catch (error) {
      $("#roster").innerHTML = '<tr><td colspan="5" class="empty-row">فهرست خوانده نشد.</td></tr>';
      toast(error.message, "error");
    }
  }

  function markDirty() {
    $("#save-state").textContent = "تغییر ذخیره‌نشده";
  }

  async function saveScores() {
    if (state.tourActive) {
      toast("حالت راهنماست؛ ذخیرهٔ نمره در تور غیرفعال است.", "warning");
      return;
    }
    const button = $("#save-scores");
    const inputs = $$("#roster .score-input");
    const updates = [];
    for (const input of inputs) {
      const record = state.drafts.get(input.dataset.record);
      if (!record) continue;
      const subjectId = input.dataset.subject;
      const existingScore = record.report.scores?.[subjectId];
      const raw = input.value.trim();
      if (!raw) {
        if (existingScore !== undefined && existingScore !== null) {
          updates.push({ record, subjectId, value: null, input });
        }
        continue;
      }
      const score = Number(normalizeDigits(raw));
      if (!Number.isFinite(score) || (!(score >= 0 && score <= 20) && score !== -1 && score !== -2)) {
        toast("نمره باید بین ۰ تا ۲۰ یا کد غیبت -۱/-۲ باشد.", "error");
        input.focus();
        return;
      }
      if (existingScore !== score) updates.push({ record, subjectId, value: score, input });
    }
    if (!updates.length) {
      $("#status").textContent = "تغییری برای ذخیره وجود ندارد.";
      $("#save-state").textContent = "همه‌چیز ذخیره شده";
      return;
    }
    button.disabled = true;
    button.textContent = "در حال ذخیره…";
    $("#save-state").textContent = "در حال ذخیره…";
    let saved = 0;
    try {
      for (const update of updates) {
        const report = update.record.report;
        const body = {
          ...report,
          id: report.id,
          revision: report.revision,
          scores: { [update.subjectId]: update.value },
        };
        const out = await api(`/api/teacher/reports/${encodeURIComponent(report.id)}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
        update.record.exists = true;
        update.record.report = { ...out.report, scores: { ...(out.report.scores || {}) } };
        update.record.report.revision = out.revision;
        update.input.dataset.record = out.report.id;
        update.input.closest("tr").dataset.record = out.report.id;
        update.input.closest("tr").dataset.existing = "1";
        update.input.closest("tr").querySelector(".row-state").textContent = `ذخیره شد توسط ${out.teacherName}`;
        state.drafts.delete(report.id);
        state.drafts.set(out.report.id, update.record);
        saved += 1;
      }
      $("#status").textContent = `${fa(saved)} نمره با موفقیت ذخیره شد.`;
      $("#save-state").textContent = `ذخیره شد · ${fa(saved)} مورد`;
    } catch (error) {
      if (error.status === 409 && error.data?.current) {
        state.conflict = error.data.current;
        $("#teacher-conflict-text").textContent =
          `${error.message} آخرین نسخه سایت آماده بارگذاری است؛ هیچ‌کدام از دو نسخه بی‌صدا بازنویسی نشد.`;
        $("#teacher-conflict").hidden = false;
        $("#save-state").textContent = "تعارض ذخیره‌سازی";
      } else {
        toast(error.message, "error");
        $("#save-state").textContent = "ذخیره کامل نشد";
      }
    } finally {
      button.disabled = false;
      button.textContent = "ذخیرهٔ نمره‌ها";
    }
  }

  function applyConflict() {
    if (!state.conflict) return;
    const record = state.drafts.get(state.conflict.id);
    if (record) {
      record.exists = true;
      record.report = { ...state.conflict, scores: { ...(state.conflict.scores || {}) } };
      state.drafts.set(state.conflict.id, record);
    }
    state.conflict = null;
    $("#teacher-conflict").hidden = true;
    loadRoster();
  }

  function confirmAction({ title, body, phrase }) {
    return new Promise((resolve) => {
      const dialog = $("#confirm-dialog");
      const form = dialog.querySelector("form");
      const input = $("#confirm-phrase");
      const error = $("#confirm-error");
      $("#confirm-title").textContent = title;
      $("#confirm-body").textContent = body;
      input.value = "";
      error.textContent = "";
      const onSubmit = (event) => {
        event.preventDefault();
        if (event.submitter?.value === "cancel") {
          cleanup();
          dialog.close();
          resolve(false);
          return;
        }
        if (input.value.trim() !== phrase) {
          error.textContent = "عبارت تأیید دقیقاً مطابق خواسته‌شده نیست.";
          return;
        }
        cleanup();
        dialog.close();
        resolve(true);
      };
      const onCancel = (event) => {
        event.preventDefault();
        cleanup();
        dialog.close();
        resolve(false);
      };
      const cleanup = () => {
        form.removeEventListener("submit", onSubmit);
        dialog.removeEventListener("cancel", onCancel);
      };
      form.addEventListener("submit", onSubmit);
      dialog.addEventListener("cancel", onCancel);
      dialog.showModal();
      input.focus();
    });
  }

  async function deleteReport(reportId, studentName) {
    const ok = await confirmAction({
      title: "حذف کارنامه",
      body: `کارنامه ${studentName} از سایت حذف می‌شود و در همگام‌سازی بعدی این حذف به اپ مدیر هم می‌رسد. این عملیات در سابقه ثبت می‌شود.`,
      phrase: "حذف کارنامه",
    });
    if (!ok) return;
    try {
      await api(`/api/teacher/reports/${encodeURIComponent(reportId)}`, { method: "DELETE" });
      toast("کارنامه حذف شد و برای مدیر ثبت می‌شود.", "success");
      loadRoster();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function saveProfile(event) {
    event.preventDefault();
    const form = event.currentTarget;
    formError(form, "");
    const data = new FormData(form);
    const body = {
      firstName: String(data.get("firstName") || "").trim(),
      lastName: String(data.get("lastName") || "").trim(),
      phone: String(data.get("phone") || "").trim(),
    };
    try {
      const out = await api("/api/me", { method: "PATCH", body: JSON.stringify(body) });
      state.user = out.user;
      $("#welcome").textContent = `${out.user.firstName} ${out.user.lastName}`;
      toast("اطلاعات حساب ذخیره شد.", "success");
    } catch (error) {
      formError(form, error.message);
    }
  }

  async function changePassword(event) {
    event.preventDefault();
    const form = event.currentTarget;
    formError(form, "");
    const data = new FormData(form);
    const newPassword = String(data.get("newPassword") || "");
    if (newPassword !== String(data.get("confirmPassword") || "")) {
      formError(form, "تکرار رمز تازه با رمز یکسان نیست.");
      return;
    }
    try {
      await api("/api/me/password", {
        method: "POST",
        body: JSON.stringify({
          currentPassword: String(data.get("currentPassword") || ""),
          newPassword,
        }),
      });
      form.reset();
      toast("رمز عبور تغییر کرد و نشست‌های قبلی باطل شدند.", "success");
    } catch (error) {
      formError(form, error.message);
    }
  }

  // -------------------------------------------------------------------------
  // Admin panel
  // -------------------------------------------------------------------------

  function metric(label, value, note = "") {
    return `<article class="metric"><span>${esc(label)}</span><b>${esc(value)}</b><small>${esc(note)}</small></article>`;
  }

  async function loadAdmin() {
    try {
      const [overview, bootstrap] = await Promise.all([
        api("/api/admin/overview"),
        api("/api/admin/bootstrap"),
      ]);
      state.bootstrap = bootstrap;
      $("#admin-version").textContent = `نسخه ${overview.version}`;
      $("#admin-overview").innerHTML = [
        metric("دانش‌آموزان", fa(overview.studentCount), "پرونده فعال"),
        metric("کارنامه‌ها", fa(overview.reportCount), "کارنامه فعال"),
        metric("معلم‌ها", fa(overview.teacherCount), `${fa(overview.activeToday)} بازدید امروز`),
        metric("بازدید هفته", fa(overview.activeWeek), `${fa(overview.adminCount)} مدیر فعال`),
      ].join("");
      await Promise.all([loadUsers(), loadStudents(), loadAudit()]);
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function loadUsers() {
    const admin = state.admin;
    const query = new URLSearchParams({ page: String(admin.usersPage), limit: "20" });
    if (admin.usersQ) query.set("q", admin.usersQ);
    try {
      const data = await api(`/api/admin/teachers?${query.toString()}`);
      $("#user-total").textContent = `${fa(data.total)} حساب`;
      $("#users-page").textContent = `صفحه ${fa(data.page)}`;
      $("#users-prev").disabled = data.page <= 1;
      $("#users-next").disabled = !data.hasMore;
      if (!data.users.length) {
        $("#users").innerHTML = '<p class="empty-state">حسابی پیدا نشد.</p>';
        return;
      }
      $("#users").innerHTML = data.users
        .map((user) => {
          const assignments = (user.assignments || [])
            .map((item) => `${classLabel(item.classId)} / ${item.subjectName}`)
            .join("، ");
          const classOptions = state.bootstrap.classes
            .map((item) => `<option value="${esc(item.id)}">${esc(classLabel(item.id))}</option>`)
            .join("");
          const subjectOptions = state.bootstrap.subjects
            .map((item) => `<option value="${esc(item.id)}">${esc(item.name)} · ${esc(item.grade || "")}</option>`)
            .join("");
          return `<article class="user-card" data-user="${esc(user.id)}">
            <header>
              <div><b>${esc(user.firstName)} ${esc(user.lastName)}</b><small>${esc(user.nationalId)} · ${esc(user.phone)}</small></div>
              <div class="user-badges"><span class="badge ${user.active ? "ok" : "off"}">${user.active ? "فعال" : "غیرفعال"}</span><span class="badge">${user.role === "admin" ? "مدیر" : "معلم"}</span></div>
            </header>
            <p class="muted">آخرین بازدید: ${esc(faDate(user.lastSeenAt))} · ورود: ${fa(user.loginCount || 0)} بار · ${fa(user.scoreActivity?.scores || 0)} ثبت نمره${user.scoreActivity?.rejected ? ` · ${fa(user.scoreActivity.rejected)} رد‌شده` : ""}</p>
            <p class="assignment-line">دسترسی: ${esc(assignments || "بدون کلاس/درس")}</p>
            <div class="admin-actions">
              <button class="button small ${user.active ? "outline" : "primary"}" type="button" data-toggle-active="${esc(user.id)}" data-active="${user.active ? "false" : "true"}">${user.active ? "غیرفعال‌کردن" : "فعال‌کردن"}</button>
              <button class="button small outline" type="button" data-change-role="${esc(user.id)}" data-role="${user.role === "admin" ? "teacher" : "admin"}">${user.role === "admin" ? "تبدیل به معلم" : "ارتقای نقش به مدیر"}</button>
            </div>
            <details>
              <summary>ویرایش دسترسی کلاس و درس</summary>
              <form data-assignment-form="${esc(user.id)}" class="stack compact-form">
                <label class="field"><span>کلاس‌ها</span><select name="classes" multiple size="5">${classOptions}</select></label>
                <label class="field"><span>درس‌ها</span><select name="subjects" multiple size="7">${subjectOptions}</select></label>
                <button class="button primary small" type="submit">ذخیرهٔ دسترسی</button>
              </form>
            </details>
          </article>`;
        })
        .join("");
      for (const user of data.users) {
        const form = $(`[data-assignment-form="${CSS.escape(user.id)}"]`, $("#users"));
        if (!form) continue;
        for (const option of form.elements.classes.options) {
          option.selected = (user.assignments || []).some((item) => item.classId === option.value);
        }
        for (const option of form.elements.subjects.options) {
          option.selected = (user.assignments || []).some((item) => item.subjectId === option.value);
        }
      }
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function patchUser(userId, body) {
    try {
      await api(`/api/admin/teachers/${encodeURIComponent(userId)}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      toast("تغییر حساب ذخیره شد.", "success");
      loadUsers();
      loadAudit();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function submitAssignments(event) {
    event.preventDefault();
    const form = event.target.closest("[data-assignment-form]");
    if (!form) return;
    const classIds = [...form.elements.classes.selectedOptions].map((option) => option.value);
    const subjectIds = [...form.elements.subjects.selectedOptions].map((option) => option.value);
    const pairs = [];
    for (const classId of classIds) {
      const klass = state.bootstrap.classes.find((item) => item.id === classId);
      for (const subjectId of subjectIds) {
        const subject = state.bootstrap.subjects.find((item) => item.id === subjectId);
        if (!klass || !subject) continue;
        if (subject.grade && String(subject.grade) !== String(klass.grade)) continue;
        if (subject.field && klass.field && subject.field !== klass.field) continue;
        pairs.push({ classId, subjectId, subjectName: subject.name });
      }
    }
    await patchUser(form.dataset.assignmentForm, { assignments: pairs });
  }

  async function loadStudents() {
    const admin = state.admin;
    const query = new URLSearchParams({ page: String(admin.studentsPage), limit: "20" });
    if (admin.studentsQ) query.set("q", admin.studentsQ);
    try {
      const data = await api(`/api/admin/students?${query.toString()}`);
      $("#student-total").textContent = `${fa(data.total)} دانش‌آموز`;
      $("#students-page").textContent = `صفحه ${fa(data.page)}`;
      $("#students-prev").disabled = data.page <= 1;
      $("#students-next").disabled = !data.hasMore;
      $("#admin-students").innerHTML = data.students.length
        ? data.students
            .map(
              (student) => `<tr>
                <td><b>${esc(student.firstName)} ${esc(student.lastName)}</b></td>
                <td>${esc(student.nationalId)}</td>
                <td>${esc(classLabel(student.classId))}</td>
                <td>${fa(student.reportCount || 0)}</td>
                <td><button class="button small outline" type="button" data-analytics="${esc(student.nationalId)}" data-name="${esc(student.firstName)} ${esc(student.lastName)}">تحلیل</button></td>
              </tr>`,
            )
            .join("")
        : '<tr><td colspan="5" class="empty-row">دانش‌آموزی پیدا نشد.</td></tr>';
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function openAnalytics(nationalId, name) {
    state.admin.analyticsNationalId = nationalId;
    state.admin.analyticsTopic = "";
    state.admin.analyticsYear = "";
    $("#analytics-panel").hidden = false;
    $("#analytics-title").textContent = `تحلیل ${name || nationalId}`;
    $("#analytics-summary").innerHTML = '<p class="muted">در حال خواندن کارنامه‌ها…</p>';
    $("#analytics-subjects").innerHTML = "";
    try {
      const data = await api(`/api/admin/students/${encodeURIComponent(nationalId)}/analytics`);
      const topic = $("#analytics-topic");
      topic.innerHTML =
        data.topics.map((item) => `<option value="${esc(item)}">${esc(item)}</option>`).join("") ||
        '<option value="">موضوعی ثبت نشده</option>';
      const year = $("#analytics-year");
      year.innerHTML =
        '<option value="">همه سال‌ها</option>' +
        data.years.map((item) => `<option value="${esc(item)}">${esc(item)}</option>`).join("");
      state.admin.analyticsTopic = data.topics[0] || "";
      topic.value = state.admin.analyticsTopic;
      if (!data.topics.length) {
        $("#analytics-summary").innerHTML = '<p class="muted">برای این دانش‌آموز کارنامه‌ای ثبت نشده است.</p>';
        return;
      }
      await loadAnalyticsScope();
    } catch (error) {
      $("#analytics-summary").innerHTML = `<p class="form-error">${esc(error.message)}</p>`;
    }
  }

  async function loadAnalyticsScope() {
    const nationalId = state.admin.analyticsNationalId;
    const topic = $("#analytics-topic").value;
    const year = $("#analytics-year").value;
    if (!nationalId || !topic) return;
    state.admin.analyticsTopic = topic;
    state.admin.analyticsYear = year;
    const query = new URLSearchParams({ reportType: topic });
    if (year) query.set("academicYear", year);
    try {
      const data = await api(
        `/api/admin/students/${encodeURIComponent(nationalId)}/analytics?${query.toString()}`,
      );
      $("#analytics-summary").innerHTML = `<p class="muted">${fa(data.reports.length)} کارنامه در محدوده «${esc(topic)}»${year ? ` و سال ${esc(year)}` : ""}. موضوع‌های دیگر در این تحلیل وارد نشده‌اند.</p>`;
      $("#analytics-subjects").innerHTML = data.subjects.length
        ? data.subjects
            .map((subject) => {
              const average = subject.average === null ? "—" : fa(subject.average);
              const trend =
                subject.trend === null
                  ? "—"
                  : subject.trend > 0
                    ? `↑ ${fa(subject.trend)}`
                    : subject.trend < 0
                      ? `↓ ${fa(Math.abs(subject.trend))}`
                      : "بدون تغییر";
              const progress =
                subject.average === null
                  ? '<span class="muted">داده کافی نیست</span>'
                  : `<progress max="20" value="${Math.max(0, Math.min(20, subject.average))}">${esc(average)}</progress>`;
              const points = subject.points
                .map((point) => `${esc(point.academicYear)}: ${point.score === -1 ? "موجه" : point.score === -2 ? "غیرموجه (۰)" : fa(point.score)}`)
                .join(" · ");
              return `<tr><td>${esc(subject.name)}</td><td>${average}</td><td>${esc(trend)}</td><td class="chart-cell">${progress}</td><td class="muted small-text">${esc(points)}</td></tr>`;
            })
            .join("")
        : '<tr><td colspan="5" class="empty-row">در این محدوده نمره‌ای ثبت نشده است.</td></tr>';
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function loadAudit() {
    const admin = state.admin;
    const query = new URLSearchParams({ page: String(admin.auditPage), limit: "25" });
    if (admin.auditQ) query.set("q", admin.auditQ);
    if (admin.auditResult) query.set("result", admin.auditResult);
    if (admin.auditKind === "admin") query.set("type", "admin");
    try {
      const data = await api(`/api/admin/audit?${query.toString()}`);
      $("#audit-page").textContent = `صفحه ${fa(data.page)}`;
      $("#audit-prev").disabled = data.page <= 1;
      $("#audit-next").disabled = !data.hasMore;
      if (admin.auditKind === "admin") {
        $("#audit-head").innerHTML = "<tr><th>مدیر</th><th>زمان</th><th>عملیات</th><th>خلاصه</th><th>نتیجه</th></tr>";
        $("#admin-audit").innerHTML = data.adminItems.length
          ? data.adminItems
              .map(
                (item) => `<tr><td>${esc(item.actorName)}</td><td>${esc(faDate(item.createdAt))}</td><td>${esc(item.action)}</td><td>${esc(item.summary || item.targetType)}</td><td><span class="badge ${item.result === "saved" ? "ok" : "warn"}">${resultLabel(item.result)}</span></td></tr>`,
              )
              .join("")
          : '<tr><td colspan="5" class="empty-row">سابقه‌ای پیدا نشد.</td></tr>';
      } else {
        $("#audit-head").innerHTML = "<tr><th>معلم</th><th>زمان</th><th>کلاس / درس</th><th>مقدار قبلی ← جدید</th><th>نتیجه</th><th>شناسه کارنامه</th></tr>";
        $("#admin-audit").innerHTML = data.items.length
          ? data.items
              .map(
                (item) => `<tr><td>${esc(item.actorName)}</td><td>${esc(faDate(item.createdAt))}</td><td>${esc(classLabel(item.classId))}<small class="block-note">${esc(item.subjectName || item.subjectId)}</small></td><td>${esc(item.oldValue ?? "—")} ← ${esc(item.newValue ?? "—")}</td><td><span class="badge ${item.result === "saved" ? "ok" : "warn"}">${resultLabel(item.result)}</span>${item.reason ? `<small class="block-note">${esc(item.reason)}</small>` : ""}</td><td class="small-text">${esc(item.reportId)}</td></tr>`,
              )
              .join("")
          : '<tr><td colspan="6" class="empty-row">سابقه‌ای پیدا نشد.</td></tr>';
      }
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function resultLabel(result) {
    return result === "saved" ? "ذخیره‌شده" : result === "rejected" ? "رد‌شده" : "ناموفق";
  }

  // -------------------------------------------------------------------------
  // Security gate, authentication and tour
  // -------------------------------------------------------------------------

  async function verifySecurityCode(value) {
    const error = $("#security-error");
    const progress = $("#security-progress");
    error.textContent = "";
    progress.textContent = "در حال بررسی کد…";
    try {
      const boot = await api("/api/bootstrap/verify", {
        method: "POST",
        body: JSON.stringify({ securityCode: value }),
      });
      state.bootstrap = boot;
      $("#classes").innerHTML =
        boot.classes
          .map(
            (item) => `<label class="choice"><input type="checkbox" name="classId" value="${esc(item.id)}"><span>${esc(item.label || [item.grade, item.field, item.section].filter(Boolean).join(" · "))}</span></label>`,
          )
          .join("") || '<p class="muted">کلاسی توسط مدیر ثبت نشده است.</p>';
      const unique = [...new Map(boot.subjects.map((item) => [item.id, item])).values()];
      $("#subjects").innerHTML =
        unique
          .map(
            (item) => `<label class="choice"><input type="checkbox" name="subjectId" value="${esc(item.id)}" data-name="${esc(item.name)}"><span>${esc(item.name)}${item.grade ? ` · پایه ${esc(item.grade)}` : ""}</span></label>`,
          )
          .join("") || '<p class="muted">درسی توسط مدیر ثبت نشده است.</p>';
      progress.textContent = "";
      window.__sampadSecurityCode = value;
      showAuthCredentials();
      setTab("login");
    } catch (caught) {
      progress.textContent = "";
      error.textContent = caught.message;
    }
  }

  async function login(event) {
    event.preventDefault();
    const form = event.currentTarget;
    formError(form, "");
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const data = Object.fromEntries(new FormData(form));
      const endpoint = String(data.nationalId || "").trim().toLowerCase() === "sampad"
        ? "/api/login"
        : "/api/teacher/login";
      await api(endpoint, { method: "POST", body: JSON.stringify(data) });
      await init();
    } catch (error) {
      formError(form, error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function register(event) {
    event.preventDefault();
    const form = event.currentTarget;
    formError(form, "");
    const data = Object.fromEntries(new FormData(form));
    if (data.password !== data.confirmPassword) {
      formError(form, "تکرار رمز عبور با رمز یکسان نیست.");
      return;
    }
    const selectedClasses = $$('input[name="classId"]:checked', form).map((input) => input.value);
    const selectedSubjects = $$('input[name="subjectId"]:checked', form).map((input) => ({
      id: input.value,
      name: input.dataset.name,
    }));
    if (!selectedClasses.length || !selectedSubjects.length) {
      formError(form, "دست‌کم یک کلاس و یک درس انتخاب کنید.");
      return;
    }
    const assignments = [];
    for (const classId of selectedClasses) {
      const klass = state.bootstrap.classes.find((item) => item.id === classId);
      for (const subject of selectedSubjects) {
        const catalogSubject = state.bootstrap.subjects.find((item) => item.id === subject.id);
        if (!klass || !catalogSubject) continue;
        if (catalogSubject.grade && String(catalogSubject.grade) !== String(klass.grade)) continue;
        if (catalogSubject.field && klass.field && catalogSubject.field !== klass.field) continue;
        assignments.push({
          classId,
          subjectId: subject.id,
          subjectName: subject.name,
        });
      }
    }
    if (!assignments.length) {
      formError(form, "هیچ ترکیب معتبری از کلاس و درس انتخاب نشده است.");
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.textContent = "در حال ساخت حساب…";
    try {
      await api("/api/register", {
        method: "POST",
        body: JSON.stringify({
          firstName: data.firstName,
          lastName: data.lastName,
          nationalId: data.nationalId,
          phone: data.phone,
          password: data.password,
          securityCode: window.__sampadSecurityCode,
          assignments,
        }),
      });
      await init();
    } catch (error) {
      formError(form, error.message);
    } finally {
      button.disabled = false;
      button.textContent = "ساخت حساب و ورود";
    }
  }

  const ADMIN_TOUR_STEPS = [
    { view: "overview", target: "#admin-overview", title: "نمای کلی مدرسه", copy: "این کارت‌ها تعداد دانش‌آموزها، کارنامه‌ها و فعالیت حساب‌ها را خلاصه می‌کنند. برای شروع هر روز، وضعیت کلی را همین‌جا ببینید.", action: "مرحله بعد را بزنید تا فهرست حساب‌ها را در صفحهٔ واقعی ببینید." },
    { view: "users", target: "#user-search-form", title: "پیدا کردن معلم", copy: "نام یا کد ملی را جست‌وجو کنید. نتیجه‌ها فقط بعد از جست‌وجو بارگذاری می‌شوند و دسترسی کلاس و درس از کارت همان معلم قابل مدیریت است.", action: "کادر جست‌وجو و دکمهٔ جست‌وجو را در همین صفحه پیدا کنید؛ در این تور نیازی به ذخیره یا تغییر دسترسی نیست." },
    { view: "students", target: "#student-search-form", title: "پرونده و تحلیل دانش‌آموز", copy: "برای دیدن کارنامه‌ها و روند یک نفر، نام یا کد ملی را وارد کنید. نتیجه فقط با جست‌وجوی شما نمایش داده می‌شود.", action: "این فرم را می‌توانید با دادهٔ نمونهٔ موجود تمرین کنید؛ جست‌وجو فقط خواندنی است." },
    { view: "activity", target: "#audit-search-form", title: "پیگیری فعالیت‌ها", copy: "از این بخش ثبت نمره‌ها و تغییرات مدیریتی را با فیلتر و صفحه‌بندی بررسی کنید.", action: "تب نمره‌ها و مدیریت را ببینید؛ این بخش فقط سابقه را می‌خواند." },
    { view: "account", target: "#profile-panel", title: "تنظیم حساب مدیر", copy: "مشخصات و رمز عبور از اینجا مدیریت می‌شوند. در تور هیچ‌کدام از فرم‌ها ارسال نمی‌شوند.", action: "برای پایان، دکمهٔ پایان را بزنید؛ حالت صفحه به نمای اصلی برمی‌گردد." },
  ];
  const TEACHER_TOUR_STEPS = [
    { target: "#class-select", title: "انتخاب کلاس", copy: "فقط کلاس‌هایی در این فهرست می‌آیند که مدیر برای شما مجاز کرده است. با تغییر کلاس، فهرست درس‌های مجاز به‌روز می‌شود.", action: "کلاس را ببینید؛ در این تور مقدار هیچ فرمی ارسال نمی‌شود." },
    { target: "#subject-select", title: "انتخاب درس", copy: "درس را انتخاب کنید و سال تحصیلی و موضوع آزمون را مشخص کنید تا نمرات همان کارنامه خوانده شوند.", action: "نمرهٔ خالی در کارنامه نمایش داده نمی‌شود." },
    { target: "#load-roster", title: "نمایش فهرست", copy: "این دکمه فهرست کلاس و نمره‌های ذخیره‌شدهٔ همان موضوع را می‌آورد. درخواست فقط برای خواندن اطلاعات است.", action: "پس از نمایش فهرست، این تور اجازهٔ ذخیرهٔ هیچ نمره‌ای را نمی‌دهد." },
    { target: "#save-scores", title: "ذخیره با کنترل", copy: "بعد از واردکردن نمرات، دکمهٔ ذخیره تغییرات را ثبت و نتیجه را اعلام می‌کند.", action: "در حالت تور ذخیره عمداً غیرفعال است؛ برای ثبت واقعی ابتدا تور را ببندید." },
    { target: "#account-button", title: "حساب و راهنما", copy: "اطلاعات حساب و تغییر رمز از «حساب من» در دسترس است و هر زمان می‌توانید راهنما را دوباره باز کنید.", action: "پایان تور هیچ دادهٔ آموزشی یا تنظیمی ذخیره نمی‌کند." },
  ];

  function offerTour() {
    if (state.tourOffered || !$("#tour-consent")?.showModal) return;
    state.tourOffered = true;
    $("#tour-consent").showModal();
  }

  function startTour() {
    if (!state.user) return;
    state.tourOffered = true;
    const isAdmin = state.user.role === "admin";
    const steps = isAdmin ? ADMIN_TOUR_STEPS : TEACHER_TOUR_STEPS;
    let index = 0;
    state.tourActive = true;
    document.body.classList.add("tour-active");
    $("#save-scores").disabled = true;
    $("#tour").hidden = false;
    $("#tour-backdrop").hidden = false;
    const finish = () => {
      $(".tour-focus")?.classList.remove("tour-focus");
      $("#tour").hidden = true;
      $("#tour-backdrop").hidden = true;
      $("#tour").style.top = "";
      $("#tour").style.left = "";
      $("#tour").style.right = "";
      $("#tour").style.bottom = "";
      document.body.classList.remove("tour-active");
      state.tourActive = false;
      if (isAdmin) setAdminView("overview");
      if ($$("#roster .score-input").length) {
        $("#save-scores").disabled = false;
        $("#status").textContent = "راهنما پایان یافت؛ تغییری ذخیره نشده است.";
      }
    };
    const render = () => {
      $(".tour-focus")?.classList.remove("tour-focus");
      const step = steps[index];
      if (isAdmin) setAdminView(step.view);
      const target = $(step.target);
      if (target) {
        target.scrollIntoView({ behavior: "auto", block: "center", inline: "nearest" });
        target.classList.add("tour-focus");
      }
      $("#tour-title").textContent = step.title;
      $("#tour-copy").textContent = step.copy;
      $("#tour-action").textContent = step.action;
      $("#tour-step-count").textContent = `مرحله ${fa(index + 1)} از ${fa(steps.length)}`;
      $("#tour-back").disabled = index === 0;
      $("#tour-next").textContent = index === steps.length - 1 ? "پایان تور" : "مرحله بعد";
      requestAnimationFrame(() => positionTourCoach(target));
    };
    $("#tour-back").onclick = () => { if (index > 0) { index -= 1; render(); } };
    $("#tour-next").onclick = () => { if (index >= steps.length - 1) finish(); else { index += 1; render(); } };
    $("#tour-close").onclick = finish;
    render();
  }

  function positionTourCoach(target) {
    const coach = $("#tour");
    if (!coach || coach.hidden) return;
    const margin = 12;
    const width = coach.offsetWidth;
    const height = coach.offsetHeight;
    const maxLeft = Math.max(margin, window.innerWidth - width - margin);
    const maxTop = Math.max(margin, window.innerHeight - height - margin);
    const rect = target?.getBoundingClientRect() || {
      left: window.innerWidth / 2, right: window.innerWidth / 2,
      top: window.innerHeight / 2, bottom: window.innerHeight / 2,
    };
    const candidates = [
      [margin, margin], [maxLeft, margin],
      [margin, maxTop], [maxLeft, maxTop],
    ];
    const score = ([left, top]) => {
      const right = left + width, bottom = top + height;
      const overlapX = Math.max(0, Math.min(right, rect.right + 18) - Math.max(left, rect.left - 18));
      const overlapY = Math.max(0, Math.min(bottom, rect.bottom + 18) - Math.max(top, rect.top - 18));
      return overlapX * overlapY;
    };
    candidates.sort((a, b) => score(a) - score(b));
    const [left, top] = candidates[0];
    coach.style.left = `${left}px`;
    coach.style.top = `${top}px`;
    coach.style.right = "auto";
    coach.style.bottom = "auto";
  }

  // -------------------------------------------------------------------------
  // Wiring
  // -------------------------------------------------------------------------

  $("#security-code").addEventListener("input", (event) => {
    const value = normalizeDigits(event.target.value).replace(/\D/g, "").slice(0, 6);
    event.target.value = value;
    $("#security-error").textContent = "";
    if (value.length === 6) verifySecurityCode(value);
  });
  $("#back-security").onclick = () => {
    window.__sampadSecurityCode = "";
    $("#security-code").value = "";
    $("#security-error").textContent = "";
    showSecurityStep();
    $("#security-code").focus();
  };
  $$(".tab[data-tab]").forEach((button) => {
    button.onclick = () => setTab(button.dataset.tab);
  });
  $("#login-form").onsubmit = login;
  $("#register-form").onsubmit = register;
  $("#class-select").onchange = updateSubjects;
  $("#load-roster").onclick = loadRoster;
  $("#roster").addEventListener("input", markDirty);
  $("#save-scores").onclick = saveScores;
  $("#reload-conflict").onclick = applyConflict;
  $("#roster").addEventListener("click", (event) => {
    const button = event.target.closest("[data-delete-report]");
    if (!button) return;
    const row = button.closest("tr");
    const name = row?.querySelector("td:nth-child(2) b")?.textContent || "";
    deleteReport(button.dataset.deleteReport, name);
  });
  $("#profile-form").onsubmit = saveProfile;
  $("#password-form").onsubmit = changePassword;
  $("#logout").onclick = async () => {
    try {
      await api("/api/logout", { method: "POST" });
    } catch {}
    location.reload();
  };
  $("#manager-logout").onclick = async () => {
    try { await api("/api/logout", { method: "POST" }); } catch {}
    location.reload();
  };
  $("#help").onclick = startTour;
  $("#account-button").onclick = () => {
    if (state.admin.view === "account") setAdminView(state.admin.returnView);
    else setAdminView("account");
  };
  $$("[data-admin-tab]").forEach((button) => {
    button.onclick = () => setAdminView(button.dataset.adminTab);
    button.onkeydown = (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const tabs = $$("[data-admin-tab]");
      const current = tabs.indexOf(button);
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 :
        (current + (event.key === "ArrowLeft" ? 1 : -1) + tabs.length) % tabs.length;
      tabs[next].focus();
      setAdminView(tabs[next].dataset.adminTab);
    };
  });

  $("#tour-consent").querySelector("form").onsubmit = (event) => {
    event.preventDefault();
    const action = event.submitter?.value || "no";
    $("#tour-consent").close();
    if (action === "yes") startTour();
  };

  document.addEventListener("submit", (event) => {
    if (!state.tourActive) return;
    const form = event.target;
    const changesData = ["profile-form", "password-form", "register-form", "login-form", "confirm-dialog"].includes(form.id) ||
      form.matches("[data-assignment-form]");
    if (!changesData) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    toast("در حالت راهنما، فرم‌ها فقط نمایشی‌اند و هیچ تغییری ثبت نمی‌شود.", "warning");
  }, true);
  document.addEventListener("click", (event) => {
    if (!state.tourActive) return;
    const writeAction = event.target.closest(
      "#save-scores, #logout, [data-toggle-active], [data-change-role], [data-delete-report], [data-assignment-form] button",
    );
    if (!writeAction) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    toast("این عملیات در حالت راهنما اجرا نمی‌شود؛ داده‌ای ثبت نخواهد شد.", "warning");
  }, true);

  $("#user-search-form").onsubmit = (event) => {
    event.preventDefault();
    state.admin.usersQ = String(new FormData(event.currentTarget).get("q") || "").trim();
    state.admin.usersPage = 1;
    loadUsers();
  };
  $("#users-prev").onclick = () => {
    if (state.admin.usersPage > 1) {
      state.admin.usersPage -= 1;
      loadUsers();
    }
  };
  $("#users-next").onclick = () => {
    state.admin.usersPage += 1;
    loadUsers();
  };
  $("#users").onclick = (event) => {
    const active = event.target.closest("[data-toggle-active]");
    if (active) {
      patchUser(active.dataset.toggleActive, { active: active.dataset.active === "true" });
      return;
    }
    const role = event.target.closest("[data-change-role]");
    if (role) patchUser(role.dataset.changeRole, { role: role.dataset.role });
  };
  $("#users").onsubmit = submitAssignments;

  $("#student-search-form").onsubmit = (event) => {
    event.preventDefault();
    state.admin.studentsQ = String(new FormData(event.currentTarget).get("q") || "").trim();
    state.admin.studentsPage = 1;
    loadStudents();
  };
  $("#students-prev").onclick = () => {
    if (state.admin.studentsPage > 1) {
      state.admin.studentsPage -= 1;
      loadStudents();
    }
  };
  $("#students-next").onclick = () => {
    state.admin.studentsPage += 1;
    loadStudents();
  };
  $("#admin-students").addEventListener("click", (event) => {
    const button = event.target.closest("[data-analytics]");
    if (button) openAnalytics(button.dataset.analytics, button.dataset.name);
  });
  $("#analytics-topic").onchange = loadAnalyticsScope;
  $("#analytics-year").onchange = loadAnalyticsScope;
  $("#close-analytics").onclick = () => {
    $("#analytics-panel").hidden = true;
    state.admin.analyticsNationalId = null;
  };

  $$(".tab[data-audit]").forEach((button) => {
    button.onclick = () => {
      state.admin.auditKind = button.dataset.audit;
      state.admin.auditPage = 1;
      $$(".tab[data-audit]").forEach((item) => item.classList.toggle("active", item === button));
      loadAudit();
    };
  });
  $("#audit-search-form").onsubmit = (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    state.admin.auditQ = String(data.get("q") || "").trim();
    state.admin.auditResult = String(data.get("result") || "");
    state.admin.auditPage = 1;
    loadAudit();
  };
  $("#audit-prev").onclick = () => {
    if (state.admin.auditPage > 1) {
      state.admin.auditPage -= 1;
      loadAudit();
    }
  };
  $("#audit-next").onclick = () => {
    state.admin.auditPage += 1;
    loadAudit();
  };

  init();
})();
