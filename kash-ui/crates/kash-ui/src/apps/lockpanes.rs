//! Settings panes: Lock Screen (passphrase + duress), Users & Groups, Notifications, About.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::apps::settings::Settings;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::icons::*;
use crate::registry::*;
use crate::text::*;
use crate::ui::*;

fn field_row(cx: &mut Ctx, g: &mut Group, id: &str, label: &str, st: &mut FieldState, ph: &str) {
    let r = cx.group_row(g);
    let lc = cx.th.label();
    cx.text(r.x + 14.0, r.cy() + 4.7, label, 13.5, Weight::Regular, lc);
    cx.text_field(id, Rect::new(r.right() - 14.0 - 236.0, r.cy() - 15.0, 236.0, 30.0), st, ph, None);
}

fn msg_line(cx: &mut Ctx, f: &mut Form, m: &(String, bool)) {
    if m.0.is_empty() { return; }
    let c = if m.1 { Color::hex(0x30D158) } else { Color::hex(0xFF453A) };
    cx.text(f.x + 6.0, f.y - 4.0, &m.0, 12.0, Weight::Medium, c);
    f.y += 16.0;
}

impl Settings {
    pub(crate) fn pane_lock(&mut self, cx: &mut Ctx, f: &mut Form) {
        // Lock now
        let r = self.card(cx, f, 96.0, Icon::Lock, 0x1C1C1E, "Lock Screen", "Ctrl Shift L · or Apple menu → Lock Screen");
        if cx.button("lock_now", Rect::new(r.right() - 18.0 - 110.0, r.cy() - 14.0, 110.0, 28.0), "Lock Now", true) { cx.cmds.push(Cmd::Lock); }

        let mut g = cx.group_begin(f, 2, 56.0);
        let mut s = cx.sys.lock_idle;
        { let r = cx.group_row(&mut g); let lc = cx.th.label(); cx.text(r.x + 14.0, r.cy() + 4.7, "Lock after inactivity", 13.5, Weight::Regular, lc);
          cx.segmented("seg_lock_idle", Rect::new(r.right() - 14.0 - 270.0, r.cy() - 14.0, 270.0, 28.0), &["Never", "1 min", "5 min", "10 min"], &mut s); }
        cx.sys.lock_idle = s;
        cx.row_value(&mut g, "Re-authentication delay", "Unavailable · timeout policy not implemented");

        cx.heading(f, "Lock screen");
        let mut g = cx.group_begin(f, 5, 50.0);
        let (mut a, mut b, mut c, mut d) = (cx.sys.lock_clock, cx.sys.lock_user, cx.sys.lock_buttons, cx.sys.lock_gateway);
        cx.row_toggle(&mut g, "lk_clock", "Show large clock", "", &mut a);
        cx.row_toggle(&mut g, "lk_user", "Show local session marker", "No account identity service is connected", &mut b);
        cx.row_toggle(&mut g, "lk_btn", "Show sleep, restart and shut down buttons", "", &mut c);
        cx.row_toggle(&mut g, "lk_gw", "Show gateway status row", "The row reports unavailable", &mut d);
        cx.row_value(&mut g, "Firmware startup screen", "Prototype sequence · preference not connected");
        cx.sys.lock_clock = a; cx.sys.lock_user = b; cx.sys.lock_buttons = c; cx.sys.lock_gateway = d;
        cx.caption(f, "Notifications are not displayed on this prototype lock screen.");

        self.pane_credentials(cx, f);
        cx.caption(f, "Display-only overlay; does not lock storage or scrub kernel keys.");
    }

    /// Passphrase + duress passphrase editors (shared by Lock Screen and Users & Groups).
    pub(crate) fn pane_credentials(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Passphrase");
        let mut g = cx.group_begin(f, 4, 48.0);
        let mut pf = core::mem::take(&mut self.pw_f);
        field_row(cx, &mut g, "pw_cur", "Current passphrase", &mut pf[0], "Required");
        field_row(cx, &mut g, "pw_new", "New passphrase", &mut pf[1], "At least 12 characters");
        field_row(cx, &mut g, "pw_ver", "Verify", &mut pf[2], "Re-enter");
        field_row(cx, &mut g, "pw_hint", "Hint (optional)", &mut pf[3], "Shown after a failed attempt");
        let br = Rect::new(f.x + f.w - 170.0, f.y - 8.0, 170.0, 30.0);
        if cx.button("pw_save", br, "Change Passphrase", true) {
            let cur_ok = cx.sys.passphrase.is_empty() || pf[0].text == cx.sys.passphrase;
            if !cur_ok { self.pw_msg = (String::from("Current passphrase is incorrect."), false); }
            else if pf[1].text.chars().count() < 12 { self.pw_msg = (String::from("Use at least 12 characters."), false); }
            else if pf[1].text != pf[2].text { self.pw_msg = (String::from("The two new passphrases don’t match."), false); }
            else if !cx.sys.duress_pass.is_empty() && pf[1].text == cx.sys.duress_pass { self.pw_msg = (String::from("Must differ from the duress passphrase."), false); }
            else {
                cx.sys.passphrase = pf[1].text.clone(); cx.sys.lock_hint = pf[3].text.clone();
                for i in 0..3 { pf[i].text.clear(); pf[i].caret = 0; }
                self.pw_msg = (String::from("Passphrase updated."), true);
                cx.cmds.push(Cmd::Toast(String::from("Passphrase updated")));
            }
        }
        let l2 = cx.th.label2();
        cx.text(f.x + 6.0, f.y + 12.0, if cx.sys.passphrase.is_empty() { "No passphrase set — first unlock will ask you to create one." } else { "Passphrase is set for this session." }, 12.0, Weight::Regular, l2);
        f.y += 38.0;
        let pm = self.pw_msg.clone(); msg_line(cx, f, &pm);
        self.pw_f = pf;

        cx.heading(f, "Duress passphrase");
        let set = !cx.sys.duress_pass.is_empty();
        let mut g = cx.group_begin(f, 4, 48.0);
        { let r = cx.group_row(&mut g); let lc = cx.th.label(); let l2 = cx.th.label2();
          cx.text(r.x + 14.0, r.cy() + 4.7, "Status", 13.5, Weight::Regular, lc);
          let c = if set { Color::hex(0x30D158) } else { l2 };
          cx.text_in(Rect::new(r.x, r.y, r.w - 14.0, r.h), if set { "Armed" } else { "Not set" }, 13.0, Weight::Medium, c, Align::Right); }
        let mut df = core::mem::take(&mut self.dz_f);
        field_row(cx, &mut g, "dz_cur", "Your passphrase", &mut df[0], "Required");
        field_row(cx, &mut g, "dz_new", "Duress passphrase", &mut df[1], "Different from your passphrase");
        field_row(cx, &mut g, "dz_ver", "Verify", &mut df[2], "Re-enter");
        let y = f.y - 8.0;
        let set_r = Rect::new(f.x + f.w - 190.0, y, 190.0, 30.0);
        if cx.button("dz_set", set_r, "Set Duress Passphrase", true) {
            let cur_ok = cx.sys.passphrase.is_empty() || df[0].text == cx.sys.passphrase;
            if !cur_ok { self.dz_msg = (String::from("Your passphrase is incorrect."), false); }
            else if df[1].text.chars().count() < 12 { self.dz_msg = (String::from("Use at least 12 characters."), false); }
            else if df[1].text == cx.sys.passphrase { self.dz_msg = (String::from("Must differ from your real passphrase."), false); }
            else if df[1].text != df[2].text { self.dz_msg = (String::from("The two entries don’t match."), false); }
            else {
                cx.sys.duress_pass = df[1].text.clone();
                for i in 0..3 { df[i].text.clear(); df[i].caret = 0; }
                self.dz_msg = (String::from("Duress passphrase armed."), true);
                cx.cmds.push(Cmd::Toast(String::from("Duress passphrase armed")));
            }
        }
        if set && cx.button("dz_clear", Rect::new(set_r.x - 112.0, y, 102.0, 30.0), "Remove", false) {
            if cx.sys.passphrase.is_empty() || df[0].text == cx.sys.passphrase { cx.sys.duress_pass.clear(); cx.sys.duress_active = false; self.dz_msg = (String::from("Duress passphrase removed."), true); }
            else { self.dz_msg = (String::from("Enter your passphrase to remove it."), false); }
        }
        f.y += 34.0;
        let dm = self.dz_msg.clone(); msg_line(cx, f, &dm);
        self.dz_f = df;
        cx.caption(f, "The UI can recognize a duress passphrase, but decoy-vault mounting, key revocation, and gateway alerts are not connected. Credentials are kept in RAM for this session only.");
        let mut g = cx.group_begin(f, 2, 48.0);
        cx.row_value(&mut g, "Erase vault keys after failed attempts", "Unavailable · no vault key service");
        cx.row_value(&mut g, "Lock on hardware-key removal", "Unavailable · no hardware-key service");
    }

    pub(crate) fn pane_users(&mut self, cx: &mut Ctx, f: &mut Form) {
        let r = Rect::new(f.x, f.y, f.w, 100.0);
        cx.group_box(r);
        cx.cv.fill_circle(r.x + 56.0, r.cy(), 32.0, Paint::Linear { p0: Pt::new(r.x + 24.0, r.y), p1: Pt::new(r.x + 88.0, r.bottom()), c0: Color::hex(0x62CBFF), c1: Color::hex(0x5A2BD2) });
        draw_kash_mark(cx.cv, Rect::new(r.x + 34.0, r.cy() - 22.0, 44.0, 44.0), Color::WHITE, Some(Color::hex(0xB6F3FF)));
        let lc = cx.th.label(); let l2 = cx.th.label2();
        cx.text(r.x + 108.0, r.cy() - 4.0, "Local session", 17.0, Weight::Semibold, lc);
        cx.text(r.x + 108.0, r.cy() + 16.0, "Single-user prototype · no account service", 12.0, Weight::Regular, l2);
        f.y += 118.0;
        let mut g = cx.group_begin(f, 2, 44.0);
        cx.row_value(&mut g, "Login options", "In-memory passphrase · no hardware key");
        let dz = if cx.sys.duress_pass.is_empty() { "Not set" } else { "Armed" };
        cx.row_value(&mut g, "Duress passphrase", dz);
        self.pane_credentials(cx, f);
    }

    pub(crate) fn pane_notifications(&mut self, cx: &mut Ctx, f: &mut Form) {
        let now = cx.sys.unix_secs; let _ = now;
        let mut g = cx.group_begin(f, 1, 52.0);
        let mut on = cx.sys.notifications;
        cx.row_toggle(&mut g, "notif_on", "Allow notifications", "", &mut on); cx.sys.notifications = on;
        if !on { cx.caption(f, "Notifications are turned off for every app."); return; }

        cx.heading(f, "Notification Center");
        let mut g = cx.group_begin(f, 2, 54.0);
        { let r = cx.group_row(&mut g); let lc = cx.th.label(); cx.text(r.x + 14.0, r.cy() + 4.7, "Show previews", 13.5, Weight::Regular, lc);
          let mut s = cx.sys.notif_preview; cx.segmented("seg_np", Rect::new(r.right() - 14.0 - 250.0, r.cy() - 14.0, 250.0, 28.0), &["Always", "Unlocked", "Never"], &mut s); cx.sys.notif_preview = s; }
        { let r = cx.group_row(&mut g); let lc = cx.th.label(); cx.text(r.x + 14.0, r.cy() + 4.7, "Group notifications", 13.5, Weight::Regular, lc);
          let mut s = cx.sys.notif_group; cx.segmented("seg_ng", Rect::new(r.right() - 14.0 - 250.0, r.cy() - 14.0, 250.0, 28.0), &["Automatic", "By App", "Off"], &mut s); cx.sys.notif_group = s; }

        cx.heading(f, "Allow notifications");
        let mut g = cx.group_begin(f, 3, 50.0);
        let (mut a, mut b, mut c) = (cx.sys.notif_locked, cx.sys.notif_sleeping, cx.sys.notif_mirror);
        cx.row_toggle(&mut g, "nl", "When the screen is locked", "Hidden entirely while Lockdown Mode is on", &mut a);
        cx.row_toggle(&mut g, "ns", "When the display is sleeping", "", &mut b);
        cx.row_toggle(&mut g, "nm", "When mirroring or sharing the display", "", &mut c);
        cx.sys.notif_locked = a; cx.sys.notif_sleeping = b; cx.sys.notif_mirror = c;

        cx.heading(f, "Application notifications");
        let list = cx.sys.reg.of_class(AppClass::Gui);
        let base = 58.0; let opt_h = 44.0; let n_opts = 5.0;
        // animated heights
        let mut hs: Vec<f32> = Vec::new(); let mut total = 0.0;
        for &i in list.iter() {
            let e = cx.anim_p(id2(id_of("nrow"), i as u32), if self.notif_open == Some(i) { 1.0 } else { 0.0 }, Preset::Smooth).clamp(0.0, 1.05);
            let h = base + e * (n_opts * opt_h + 44.0);
            hs.push(h); total += h;
        }
        let box_r = Rect::new(f.x, f.y, f.w, total.max(base));
        cx.group_box(box_r);
        let mut y = f.y;
        for (k, &i) in list.iter().enumerate() {
            let h = hs[k];
            let row = Rect::new(f.x, y, f.w, base);
            let full = Rect::new(f.x, y, f.w, h);
            if k > 0 { let c = cx.th.separator(); cx.cv.fill_rect(Rect::new(row.x + 14.0, row.y, row.w - 14.0, 1.0), c); }
            let (name, kind, blocked) = { let a = &cx.sys.reg.apps[i]; (a.name.clone(), a.kind, cx.sys.reg.blocked(i) || a.perms[Perm::Notifications.idx()] == PS::Deny) };
            let mut st = cx.sys.notif_apps[i];
            let hit = cx.hit(id_of(&name) ^ 0x7C1, row);
            if hit.hovered && self.notif_open != Some(i) { let hf = cx.th.hover_fill(); cx.cv.fill_rrect(row.inset(2.0), 10.0, hf); }
            if hit.clicked { self.notif_open = if self.notif_open == Some(i) { None } else { Some(i) }; }
            if let Some(k2) = kind { cx.app_icon(k2, Rect::new(row.x + 12.0, row.cy() - 17.0, 34.0, 34.0)); }
            let lc = cx.th.label(); let l2 = cx.th.label2();
            cx.text(row.x + 58.0, row.cy() - 2.0, &name, 13.5, Weight::Regular, lc);
            let sub = if blocked { String::from("Blocked in Privacy & Security") } else if !st.allow { String::from("Off") } else { format!("{}{}{}", ["None", "Banners", "Alerts"][st.style.min(2)], if st.sounds { " · Sounds" } else { "" }, if st.badges { " · Badges" } else { "" }) };
            cx.text(row.x + 58.0, row.cy() + 13.0, &sub, 11.5, Weight::Regular, l2);
            let e = ((h - base) / (n_opts * opt_h + 44.0)).clamp(0.0, 1.0);
            let ch = Rect::new(row.right() - 30.0, row.cy() - 7.0, 14.0, 14.0);
            if e > 0.5 { draw_icon(cx.cv, Icon::ChevD, ch, l2); } else { draw_icon(cx.cv, Icon::ChevR, ch, l2); }
            if h > base + 1.0 && !blocked {
                cx.cv.push_clip(full);
                let mut oy = y + base;
                let sep = cx.th.separator();
                let rows: [(&str, u8); 6] = [("Allow notifications", 0), ("Alert style", 1), ("Badge app icon", 2), ("Play sound for notifications", 3), ("Show on lock screen", 4), ("Show in Notification Center", 5)];
                for (ri, (lab, kd)) in rows.iter().enumerate() {
                    let rr = Rect::new(f.x, oy, f.w, if ri == 0 { 44.0 } else { opt_h });
                    cx.cv.fill_rect(Rect::new(rr.x + 14.0, rr.y, rr.w - 14.0, 1.0), sep);
                    cx.text(rr.x + 58.0, rr.cy() + 4.7, lab, 13.0, Weight::Regular, lc);
                    let id = format!("na{}_{}", i, kd);
                    let tg = Rect::new(rr.right() - 14.0 - 40.0, rr.cy() - 11.0, 40.0, 22.0);
                    match kd {
                        0 => { cx.toggle(&id, tg, &mut st.allow); }
                        1 => { let mut s = st.style; cx.segmented(&id, Rect::new(rr.right() - 14.0 - 210.0, rr.cy() - 13.0, 210.0, 26.0), &["None", "Banners", "Alerts"], &mut s); st.style = s; }
                        2 => { cx.toggle(&id, tg, &mut st.badges); }
                        3 => { cx.toggle(&id, tg, &mut st.sounds); }
                        4 => { cx.toggle(&id, tg, &mut st.lock_screen); }
                        _ => { cx.toggle(&id, tg, &mut st.center); }
                    }
                    oy += opt_h;
                }
                cx.cv.pop_clip();
            }
            cx.sys.notif_apps[i] = st;
            y += h;
        }
        f.y += total.max(base) + 18.0;
        cx.caption(f, "Per-app permission to send notifications at all lives in Privacy & Security → Notifications.");
    }

    pub(crate) fn pane_about(&mut self, cx: &mut Ctx, f: &mut Form) {
        let r = Rect::new(f.x, f.y, f.w, 232.0);
        cx.group_box(r);
        cx.app_icon(AppKind::About, Rect::new(r.cx() - 52.0, r.y + 22.0, 104.0, 104.0));
        let lc = cx.th.label(); let l2 = cx.th.label2();
        cx.text_in(Rect::new(r.x, r.y + 136.0, r.w, 30.0), "KashOS", 26.0, Weight::Bold, lc, Align::Center);
        cx.text_in(Rect::new(r.x, r.y + 166.0, r.w, 20.0), &format!("Development build · {}", env!("CARGO_PKG_VERSION")), 13.0, Weight::Regular, l2, Align::Center);
        let b = Rect::new(r.cx() - 62.0, r.y + 192.0, 124.0, 28.0);
        if cx.button("about_upd", b, "Software Update…", false) { cx.sys.settings_pane_request = Some(19); }
        f.y += 250.0;

        cx.heading(f, "Device");
        let mut g = cx.group_begin(f, 7, 40.0);
        cx.row_value(&mut g, "Session", "Local · account service unavailable");
        cx.row_value(&mut g, "Processor", "x86-64 build target · CPU inventory unavailable");
        cx.row_value(&mut g, "Memory", "Runtime total unavailable");
        cx.row_value(&mut g, "Startup source", "Unavailable · no boot-device report");
        cx.row_value(&mut g, "Framebuffer", &format!("{} × {} · refresh rate unavailable", cx.sys.display_output.w as i32, cx.sys.display_output.h as i32));
        cx.row_value(&mut g, "Hardware serial", "Unavailable · no firmware inventory");
        let up = cx.io.time as i64;
        cx.row_value(&mut g, "UI session time", &format!("{} min {} s", up / 60, up % 60));

        cx.heading(f, "System");
        let mut g = cx.group_begin(f, 5, 40.0);
        cx.row_value(&mut g, "Kernel", &format!("KashOS kernel {}", env!("CARGO_PKG_VERSION")));
        cx.row_value(&mut g, "Capability self-tests", "Boot log only · not reported to UI");
        cx.row_value(&mut g, "Encrypted vault", "Status unavailable · no UI service feed");
        let (a, k, d) = cx.sys.reg.totals(); let _ = (a, k, d);
        let tot = cx.sys.reg.apps.len();
        cx.row_value(&mut g, "UI demo registry", &format!("{} built-in demos · no package inventory", tot));
        cx.row_value(&mut g, "Lockdown demo", if cx.sys.reg.lockdown { "On" } else { "Off" });

        cx.heading(f, "Kash UI");
        let mut g = cx.group_begin(f, 6, 40.0);
        cx.row_value(&mut g, "Version", env!("CARGO_PKG_VERSION"));
        cx.row_value(&mut g, "Crate", "kash-ui · Rust 2021 · no_std + alloc");
        cx.row_value(&mut g, "Renderer", "Software · 0x00RRGGBB framebuffer");
        cx.row_value(&mut g, "Effects", "Liquid Glass · spring animations");
        cx.row_value(&mut g, "Typefaces", "Inter · DejaVu Sans Mono");
        cx.row_value(&mut g, "License", "MIT");
        cx.caption(f, "© Kash Labs. KashOS and Kash UI are built entirely in Rust.");
    }
}
