//! Small server-rendered HTML pages used by the ad-monetization flows.

use axum::response::{Html, IntoResponse, Response};

/// Escape a string for safe insertion into an HTML attribute value.
pub fn html_attr_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Interstitial page shown *before* the arolinks ad. It explains what will
/// happen, offers a Proceed button, and auto-redirects to `target_url` after 3s
/// so users know the link is genuine. `action_desc` completes the sentence
/// "After you complete it, ...".
pub fn ad_interstitial_page(target_url: &str, action_desc: &str) -> Response {
    let href = html_attr_escape(target_url);
    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Please wait</title><style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}.card{{background:#1a1f2e;border:1px solid #2d3748;border-radius:16px;padding:40px 32px;max-width:460px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.4)}}.emoji{{font-size:3rem;margin-bottom:16px}}h1{{font-size:1.4rem;color:#63b3ed;margin-bottom:12px}}p{{color:#a0aec0;font-size:1rem;line-height:1.6;margin-bottom:12px}}.count{{color:#68d391;font-weight:700}}.btn{{display:inline-block;margin-top:20px;background:#2b6cb0;color:#fff;text-decoration:none;border-radius:8px;padding:12px 32px;font-size:1rem;font-weight:600;cursor:pointer}}.btn:hover{{background:#3182ce}}.note{{margin-top:16px;font-size:.8rem;color:#718096}}</style></head><body><div class="card"><div class="emoji">&#127916;</div><h1>One quick ad first</h1><p>You'll be shown a short ad. After you complete it, {action_desc}.</p><p>Continuing in <span class="count" id="count">3</span>s&hellip;</p><a class="btn" id="go" href="{href}" data-target="{href}" rel="noopener">Proceed now &rarr;</a><div class="note">This link is valid &mdash; thanks for supporting us!</div></div><script>(function(){{var go=document.getElementById('go');var target=go.getAttribute('data-target');go.addEventListener('click',function(e){{e.preventDefault();window.location.href=target;}});var n=3;var c=document.getElementById('count');var timer=setInterval(function(){{n-=1;if(c){{c.textContent=n<0?0:n;}}if(n<=0){{clearInterval(timer);window.location.href=target;}}}},1000);}})();</script></body></html>"#
    );
    Html(html).into_response()
}

/// Human-readable duration like "1 day 4 hours" or "8 hours 5 min".
pub fn human_duration(secs: f64) -> String {
    let secs = secs.max(0.0) as u64;
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!(
            "{} day{} {} hour{}",
            days,
            if days == 1 { "" } else { "s" },
            hours,
            if hours == 1 { "" } else { "s" }
        )
    } else if hours > 0 {
        format!(
            "{} hour{} {} min",
            hours,
            if hours == 1 { "" } else { "s" },
            mins
        )
    } else {
        format!("{} min", mins)
    }
}

/// Render a simple dark-themed message page.
fn message_page(emoji: &str, title: &str, message: &str, accent: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>{title}</title><style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}.card{{background:#1a1f2e;border:1px solid #2d3748;border-radius:16px;padding:40px 32px;max-width:440px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.4)}}.emoji{{font-size:3rem;margin-bottom:16px}}h1{{font-size:1.4rem;color:{accent};margin-bottom:12px}}p{{color:#a0aec0;font-size:1rem;line-height:1.6}}</style></head><body><div class="card"><div class="emoji">{emoji}</div><h1>{title}</h1><p>{message}</p></div></body></html>"#
    );
    Html(html).into_response()
}

pub fn ad_token_active_page(remaining: f64) -> Response {
    message_page(
        "\u{2705}",
        "You're already covered",
        &format!(
            "You already have an active ad-free token. No ads will be shown for about {}.",
            human_duration(remaining)
        ),
        "#68d391",
    )
}

pub fn ad_token_incremented_page(remaining: f64) -> Response {
    message_page(
        "\u{1F389}",
        "Ad-free time extended",
        &format!(
            "Your ad-free token was extended by 12 hours. You now have about {} of ad-free access.",
            human_duration(remaining)
        ),
        "#63b3ed",
    )
}

pub fn ad_token_unavailable_page() -> Response {
    message_page(
        "\u{1F6E0}",
        "Temporarily unavailable",
        "The ad-token service is not available right now. Please try again later.",
        "#f6ad55",
    )
}

pub fn ad_token_invalid_page() -> Response {
    message_page(
        "\u{26A0}",
        "Invalid link",
        "This ad-token link is malformed.",
        "#fc8181",
    )
}

pub fn ad_token_ads_off_page() -> Response {
    message_page(
        "&#127881;",
        "No ads right now",
        "Ads are currently turned off - downloads and streams are ad-free for everyone. Enjoy!",
        "#68d391",
    )
}
