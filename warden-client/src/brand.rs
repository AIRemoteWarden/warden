pub const APP_NAME: &str = "AI Remote Warden";
pub const APP_BANNER: &str = r#"
   ___   ____  _      __            __
  / _ | /  _/ | | /| / /__ ________/ /__ ___
 / __ |_/ /   | |/ |/ / _ `/ __/ _  / -_) _ \
/_/ |_/___/   |__/|__/\_,_/_/  \_,_/\__/_//_/"#;

pub fn app_slug() -> String {
    APP_NAME
        .chars()
        .map(|ch| match ch {
            'A'..='Z' => ch.to_ascii_lowercase(),
            'a'..='z' | '0'..='9' => ch,
            _ => '-',
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn approval_prompt() -> String {
    format!("{APP_NAME} approval> ")
}

pub fn denied_message() -> String {
    format!("{APP_NAME}: command denied by host")
}

pub fn offline_session_id() -> String {
    format!("{}-session-dev", app_slug())
}

pub fn offline_host_token() -> String {
    format!("{}-host-token-dev", app_slug())
}

pub fn offline_guest_url() -> String {
    format!("http://{}.local/session-dev#local-key", app_slug())
}

pub fn hook_dir_prefix() -> String {
    format!("{}-hook", app_slug())
}
