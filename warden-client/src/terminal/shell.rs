#[derive(Debug, Clone)]
pub struct ShellSpec {
    pub kind: ShellKind,
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ShellKind {
    Bash,
    Zsh,
    PowerShell,
}
