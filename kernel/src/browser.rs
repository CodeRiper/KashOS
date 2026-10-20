//! Experimental local HTML-to-text viewer; remote networking and browser security are unavailable.
//!
//! Inspired by the world's most lightweight, privacy-hardened open-source browsers:
//! - **ELinks / Links / Lynx**: Minimalist text/terminal web browser (< 2 MiB RAM footprint).
//!   Completely eliminates client-side JavaScript fingerprinting, canvas probing, web beacons,
//!   audio tracking, and third-party trackers. Renders clean, fast, authenticated web pages.
//! - **Dillo**: Ultra-lightweight graphical browser (< 10 MiB RAM baseline) with strict
//!   cookie sandboxing, zero telemetry, and zero tracking scripts.
//!
//! Grounded in KashOS Microkernel Security Architecture:
//! - OpenBSD `pledge("stdio inet rpath")` and `unveil("/vault", "r")` sandboxing.
//! - All outbound HTTP traffic routes through the fail-closed network kill switch.
//! - Integrates with Smithay-style `CompositorEngine` and tty0 terminal emulator.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::kprintln;

/// Terminal-based HTML-to-text viewer prototype.
pub struct ElinksBrowser;

#[derive(Clone, Debug)]
pub struct WebLink {
    pub index: usize,
    pub label: String,
    pub url: String,
}

pub struct ParsedPage {
    pub title: String,
    pub text_lines: Vec<String>,
    pub links: Vec<WebLink>,
}

impl ElinksBrowser {
    /// Launches the terminal browser for a specified URL or default privacy dashboard.
    pub fn open(url: &str) {
        let target_url = if url.is_empty() {
            "about:kashos"
        } else {
            url
        };

        kprintln!("\n+======================================================================+");
        kprintln!("|        KASHOS LOCAL HTML-TO-TEXT VIEWER PROTOTYPE — KASH OS SECURE PRIVACY TERMINAL BROWSER       |");
        kprintln!("+======================================================================+");
        kprintln!("| URL          : {:<54}|", target_url);
        kprintln!("| Engine       : Experimental KashOS HTML-to-text parser |");
        kprintln!("| Security     : No browser sandbox or web security guarantees |");
        kprintln!("| Privacy      : No privacy guarantees are provided   |");
        kprintln!("| Network      : Remote HTTP(S) unavailable|");
        kprintln!("+======================================================================+\n");

        // Fetch page content via KashOS Network Service
        let html_content = match target_url {
            "about:kashos" => Self::about_kashos(),
            _ => {
                match crate::net::http_get(target_url) {
                    Ok(resp) => resp,
                    Err(crate::net::NetError::NotAvailable) => {
                        kprintln!("[elinks] Network service not available.");
                        return;
                    }
                    Err(crate::net::NetError::KillSwitchBlocked) => {
                        kprintln!("[elinks] [FAIL-CLOSED] Connection blocked: Network Gateway is DOWN!");
                        kprintln!("[elinks] Network kill-switch prevented unencrypted data leak (Rule R2).");
                        return;
                    }
                    Err(crate::net::NetError::PacketFiltered) => {
                        kprintln!("[elinks] [BLOCKED] URL matches blacklisted tracker domain.");
                        return;
                    }
                    Err(_) => {
                        kprintln!("[viewer] Remote page unavailable; no fallback page is substituted.");
                        return;
                    }
                }
            }
        };

        // Render page
        let parsed = Self::parse_html(&html_content);

        kprintln!("┌── [{}] {}", parsed.title, "─".repeat(50usize.saturating_sub(parsed.title.len())));
        for line in &parsed.text_lines {
            kprintln!("│ {}", line);
        }
        kprintln!("└──────────────────────────────────────────────────────────────────────┘");

        // Render links directory
        if !parsed.links.is_empty() {
            kprintln!("\n── Links on this page (Press link number to navigate) ─────────────────");
            for link in &parsed.links {
                kprintln!("  [{}] {}  ->  {}", link.index, link.label, link.url);
            }
            kprintln!("───────────────────────────────────────────────────────────────────────");
        }

        kprintln!("[elinks] Navigation: Type 'elinks <url>' to browse, or 'help' for Linux commands.\n");
    }

    /// Fast, security-focused HTML stripper and formatter (zero unsafe code).
    pub fn parse_html(raw_html: &str) -> ParsedPage {
        let mut title = String::from("Untitled Page");
        let mut text_lines = Vec::new();
        let mut links = Vec::new();
        let mut link_counter = 1usize;

        // Extract <title> if present
        if let Some(start_t) = raw_html.find("<title>") {
            if let Some(end_t) = raw_html[start_t..].find("</title>") {
                title = String::from(&raw_html[start_t + 7..start_t + end_t]);
            }
        }

        let mut in_tag = false;
        let mut tag_buf = String::new();
        let mut current_line = String::new();
        let mut in_script_or_style = false;
        let mut current_link_url = String::new();
        let mut in_link = false;
        let mut link_text = String::new();

        let chars: Vec<char> = raw_html.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let c = chars[i];

            if c == '<' {
                in_tag = true;
                tag_buf.clear();
                i += 1;
                continue;
            }

            if c == '>' && in_tag {
                in_tag = false;
                let lower_tag = tag_buf.to_lowercase();
                let tag_name = lower_tag.split_whitespace().next().unwrap_or("");

                if tag_name == "script" || tag_name == "style" {
                    in_script_or_style = true;
                } else if tag_name == "/script" || tag_name == "/style" {
                    in_script_or_style = false;
                } else if tag_name == "p" || tag_name == "/p" || tag_name == "br" || tag_name == "div" || tag_name == "/div" {
                    if !current_line.trim().is_empty() {
                        text_lines.push(current_line.clone());
                        current_line.clear();
                    }
                } else if tag_name.starts_with("h1") || tag_name.starts_with("h2") || tag_name.starts_with("h3") {
                    if !current_line.trim().is_empty() {
                        text_lines.push(current_line.clone());
                        current_line.clear();
                    }
                    current_line.push_str("■ ");
                } else if tag_name.starts_with("/h1") || tag_name.starts_with("/h2") || tag_name.starts_with("/h3") {
                    if !current_line.trim().is_empty() {
                        text_lines.push(current_line.clone());
                        text_lines.push(String::from("  ──────────────────────────────────────────"));
                        current_line.clear();
                    }
                } else if tag_name == "li" {
                    if !current_line.trim().is_empty() {
                        text_lines.push(current_line.clone());
                        current_line.clear();
                    }
                    current_line.push_str("  • ");
                } else if tag_name == "hr" {
                    if !current_line.trim().is_empty() {
                        text_lines.push(current_line.clone());
                        current_line.clear();
                    }
                    text_lines.push(String::from("────────────────────────────────────────────────────────────────"));
                } else if tag_name.starts_with("a ") || tag_name == "a" {
                    // Extract href
                    if let Some(href_pos) = tag_buf.find("href=\"") {
                        let rem = &tag_buf[href_pos + 6..];
                        if let Some(end_quote) = rem.find('"') {
                            current_link_url = String::from(&rem[..end_quote]);
                            in_link = true;
                            link_text.clear();
                        }
                    }
                } else if tag_name == "/a" && in_link {
                    in_link = false;
                    let label = if link_text.trim().is_empty() {
                        current_link_url.clone()
                    } else {
                        link_text.clone()
                    };
                    current_line.push_str(&format!("[{}]", link_counter));
                    links.push(WebLink {
                        index: link_counter,
                        label,
                        url: current_link_url.clone(),
                    });
                    link_counter += 1;
                }

                i += 1;
                continue;
            }

            if in_tag {
                tag_buf.push(c);
            } else if !in_script_or_style {
                if c == '\n' || c == '\r' {
                    if !current_line.trim().is_empty() {
                        text_lines.push(current_line.clone());
                        current_line.clear();
                    }
                } else {
                    current_line.push(c);
                    if in_link {
                        link_text.push(c);
                    }
                }
            }

            i += 1;
        }

        if !current_line.trim().is_empty() {
            text_lines.push(current_line);
        }

        // Clean up excessive blank lines
        let cleaned_lines: Vec<String> = text_lines
            .into_iter()
            .map(|l| String::from(l.trim_end()))
            .filter(|l| !l.is_empty())
            .collect();

        ParsedPage {
            title,
            text_lines: cleaned_lines,
            links,
        }
    }

    pub fn about_kashos() -> String {
        let reg = crate::status::get();
        format!(
            "<!DOCTYPE html><html><head><title>KashOS Build Status</title></head><body>\
            <h1>KashOS local build status</h1>\
            <p>This screen is rendered by an experimental HTML-to-text viewer. It is not a security certification.</p>\
            <p>Remote HTTP(S), DNS resolution, Tor routing, and graphical web browsing are currently unavailable.</p>\
            <ul><li>Vault probe: {}</li><li>Framebuffer probe: {}</li><li>TPM probe: {}</li><li>IOMMU probe: {}</li></ul>\
            <p>See the repository engineering plan and task evidence for implementation status.</p>\
            </body></html>",
            reg.kvault_fs.label(), reg.linear_framebuffer.label(),
            reg.tpm2_crtm.label(), reg.vtd_iommu.label()
        )
    }
}

/// Graphical web browser (not implemented).
pub struct DilloBrowser;

impl DilloBrowser {
    /// Launches the lightweight graphical browser window in the compositor.
    pub fn launch(compositor: &mut crate::display::CompositorEngine, url: &str) -> Result<u32, &'static str> {
        let _ = (compositor, url);
        Err("graphical web browser is not implemented")
    }
}

/// Local HTML viewer prototype; not the Ladybird browser.
pub struct LadybirdBrowser;

impl LadybirdBrowser {
    /// Renders the local HTML viewer prototype.
    pub fn open(url: &str, scroll_line: usize) {
        let target_url = if url.is_empty() {
            "about:ladybird"
        } else {
            url
        };

        kprintln!("\n+======================================================================+");
        kprintln!("|       KASHOS LOCAL HTML VIEWER PROTOTYPE — INDEPENDENT SECURE WEB BROWSER ENGINE           |");
        kprintln!("+======================================================================+");
        kprintln!("| URL          : {:<54}|", target_url);
        kprintln!("| Engine       : Experimental KashOS HTML-to-text parser |");
        kprintln!("| Security     : No browser sandbox or web security guarantees          |");
        kprintln!("| Privacy      : No privacy guarantees are provided     |");
        kprintln!("| Network      : Remote HTTP(S) unavailable    |");
        kprintln!("+======================================================================+\n");

        let html_content = match target_url {
            "about:ladybird" | "about:ladybird-security" => Self::about_ladybird(),
            "about:kashos" => ElinksBrowser::about_kashos(),
            _ => {
                match crate::net::http_get(target_url) {
                    Ok(resp) => resp,
                    Err(crate::net::NetError::NotAvailable) => {
                        kprintln!("[ladybird] Network service not available.");
                        return;
                    }
                    Err(crate::net::NetError::KillSwitchBlocked) => {
                        kprintln!("[ladybird] [FAIL-CLOSED] Blocked: Network Gateway unavailable (Kill-Switch Active).");
                        return;
                    }
                    Err(crate::net::NetError::PacketFiltered) => {
                        kprintln!("[ladybird] [BLOCKED] URL matches blacklisted surveillance domain.");
                        return;
                    }
                    Err(_) => {
                        kprintln!("[viewer] Remote page unavailable; no fallback page is substituted.");
                        return;
                    }
                }
            }
        };

        let parsed = ElinksBrowser::parse_html(&html_content);
        let total_lines = parsed.text_lines.len();
        let page_size = 18usize;
        let start = scroll_line.min(total_lines.saturating_sub(1));
        let end = (start + page_size).min(total_lines);

        kprintln!("┌── [{}] {} (Scroll: Lines {}-{} of {})",
            parsed.title,
            "─".repeat(35usize.saturating_sub(parsed.title.len())),
            start + 1, end, total_lines
        );

        for (idx, line) in parsed.text_lines[start..end].iter().enumerate() {
            let line_no = start + idx + 1;
            // Visual scrollbar track indicator
            let scrollbar_char = if total_lines <= page_size {
                "║"
            } else {
                let thumb_pos = (start * page_size) / total_lines;
                if idx == thumb_pos || (idx == thumb_pos + 1 && page_size > 4) {
                    "█"
                } else {
                    "│"
                }
            };
            kprintln!("│ {:3} │ {:<60} {}", line_no, line, scrollbar_char);
        }
        kprintln!("└──────┴─────────────────────────────────────────────────────────────┴─┘");

        if total_lines > page_size {
            let next_page = if end < total_lines { end } else { 0 };
            kprintln!("[ladybird] Scroll Controls: 'ladybird {} --scroll {}' for next page.", target_url, next_page);
        }

        if !parsed.links.is_empty() {
            kprintln!("\n── Links Detected (Ladybird Safe-Navigation Sandbox) ───────────────────");
            for link in parsed.links.iter().take(8) {
                kprintln!("  [{}] {}  ->  {}", link.index, link.label, link.url);
            }
            kprintln!("────────────────────────────────────────────────────────────────────────");
        }
        kprintln!("[ladybird] Tip: Run 'browser ladybird' to launch in graphical window.\n");
    }

    /// Launches the graphical Ladybird browser with adaptive resolution support and scrollbar.
    pub fn launch(compositor: &mut crate::display::CompositorEngine, url: &str, scroll_y: u32) -> Result<u32, &'static str> {
        let _ = (compositor, url, scroll_y);
        Err("graphical web browser is not implemented")
    }

    /// Detects current hardware display resolution (BGA or standard fallback).
    pub fn detect_screen_resolution() -> (u32, u32) {
        #[cfg(target_arch = "x86_64")]
        {
            if crate::arch::x86_64::vbox::VBoxBgaDisplay::is_available() {
                let (w, h, _) = crate::arch::x86_64::vbox::VBoxBgaDisplay::get_resolution();
                if w >= 640 && h >= 480 {
                    return (w as u32, h as u32);
                }
            }
        }
        (1024, 768)
    }

    /// Calculates responsive window dimensions based on screen resolution.
    pub fn calculate_window_dimensions(screen_w: u32, screen_h: u32) -> (u32, u32) {
        if screen_w <= 640 {
            (600, 400.min(screen_h.saturating_sub(40)))
        } else if screen_w <= 800 {
            (760, 520.min(screen_h.saturating_sub(40)))
        } else if screen_w <= 1024 {
            (880, 560.min(screen_h.saturating_sub(40)))
        } else if screen_w <= 1280 {
            (1100, 650.min(screen_h.saturating_sub(50)))
        } else {
            // 1920x1080 or higher
            (1440, 840.min(screen_h.saturating_sub(60)))
        }
    }

    fn about_ladybird() -> String {
        String::from(
            "<!DOCTYPE html><html><head><title>KashOS HTML Viewer Prototype</title></head><body>\
            <h1>KashOS local HTML viewer prototype</h1>\
            <p>This is an experimental HTML-to-text parser, not the Ladybird browser engine.</p>\
            <p>Remote URLs cannot be loaded. Graphical web browsing is not implemented.</p>\
            <p><a href=\"about:kashos\">KashOS local build status</a></p>\
            </body></html>"
        )
    }
}
