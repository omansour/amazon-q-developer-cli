use std::io::Write;

use crossterm::queue;
use crossterm::style::{
    self,
    Color,
};
use eyre::Result;
use regex::Regex;
use serde::Deserialize;
use tracing::error;

use crate::cli::agent::{
    Agent,
    PermissionEvalResult,
};
use crate::cli::chat::sanitize_unicode_tags;
use crate::cli::chat::tools::{
    InvokeOutput,
    MAX_TOOL_RESPONSE_SIZE,
    OutputKind,
};
use crate::cli::chat::util::truncate_safe;
use crate::os::Os;

// Platform-specific modules
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(not(windows))]
mod unix;
#[cfg(not(windows))]
pub use unix::*;

// Common readonly commands that are safe to execute without user confirmation
pub const READONLY_COMMANDS: &[&str] = &[
    "ls", "cat", "echo", "pwd", "which", "head", "tail", "find", "grep", "dir", "type",
];

#[derive(Debug, Clone, Deserialize)]
pub struct ExecuteCommand {
    pub command: String,
    pub summary: Option<String>,
}

impl ExecuteCommand {
    pub fn requires_acceptance(&self, allowed_commands: Option<&Vec<String>>, allow_read_only: bool) -> bool {
        let default_arr = vec![];
        let allowed_commands = allowed_commands.unwrap_or(&default_arr);

        let has_regex_match = allowed_commands
            .iter()
            .map(|cmd| Regex::new(&format!(r"\A{}\z", cmd)))
            .filter(Result::is_ok)
            .flatten()
            .any(|regex| regex.is_match(&self.command));
        if has_regex_match {
            return false;
        }

        let Some(args) = shlex::split(&self.command) else {
            return true;
        };
        const DANGEROUS_PATTERNS: &[&str] = &["<(", "$(", "`", ">", "&&", "||", "&", ";"];

        if args
            .iter()
            .any(|arg| DANGEROUS_PATTERNS.iter().any(|p| arg.contains(p)))
        {
            return true;
        }

        // Split commands by pipe and check each one
        let mut current_cmd = Vec::new();
        let mut all_commands = Vec::new();

        for arg in args {
            if arg == "|" {
                if !current_cmd.is_empty() {
                    all_commands.push(current_cmd);
                }
                current_cmd = Vec::new();
            } else if arg.contains("|") {
                // if pipe appears without spacing e.g. `echo myimportantfile|args rm` it won't get
                // parsed out, in this case - we want to verify before running
                return true;
            } else {
                current_cmd.push(arg);
            }
        }
        if !current_cmd.is_empty() {
            all_commands.push(current_cmd);
        }

        // Check if each command in the pipe chain starts with a safe command
        for cmd_args in all_commands {
            match cmd_args.first() {
                // Special casing for `find` so that we support most cases while safeguarding
                // against unwanted mutations
                Some(cmd)
                    if cmd == "find"
                        && cmd_args.iter().any(|arg| {
                            arg.contains("-exec") // includes -execdir
                                || arg.contains("-delete")
                                || arg.contains("-ok") // includes -okdir
                        }) =>
                {
                    return true;
                },
                Some(cmd) => {
                    // Check if command matches any allowed pattern (exact match or wildcard)
                    if Self::command_matches_allowed_patterns(cmd, &cmd_args.join(" "), allowed_commands) {
                        continue;
                    }
                    // Special casing for `grep`. -P flag for perl regexp has RCE issues, apparently
                    // should not be supported within grep but is flagged as a possibility since this is perl
                    // regexp.
                    if cmd == "grep" && cmd_args.iter().any(|arg| arg.contains("-P")) {
                        return true;
                    }
                    let is_cmd_read_only = READONLY_COMMANDS.contains(&cmd.as_str());
                    if !allow_read_only || !is_cmd_read_only {
                        return true;
                    }
                },
                None => return true,
            }
        }

        false
    }

    /// Check if a command matches any of the allowed patterns.
    /// Supports both exact string matching and wildcard patterns.
    fn command_matches_allowed_patterns(cmd: &str, full_command: &str, allowed_commands: &[String]) -> bool {
        for pattern in allowed_commands {
            // First try exact string matching for backward compatibility
            // Check both the first word and the full command
            if pattern == cmd || pattern == full_command {
                return true;
            }

            // Then try wildcard pattern matching
            if pattern.contains('*') {
                // For wildcard patterns, we need to decide what to match against
                let match_target = if pattern.starts_with(cmd) {
                    // If pattern starts with the command name, match against full command
                    // e.g., "git commit*" should match "git commit -m message"
                    full_command
                } else {
                    // Otherwise, match against just the command name
                    // e.g., "git*" should match "git"
                    cmd
                };

                if let Ok(glob) = globset::Glob::new(pattern) {
                    if glob.compile_matcher().is_match(match_target) {
                        return true;
                    }
                } else {
                    // If glob pattern is invalid, log warning and fall back to exact match
                    tracing::warn!("Invalid glob pattern in allowedCommands: {}", pattern);
                    if pattern == cmd || pattern == full_command {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub async fn invoke(&self, output: &mut impl Write) -> Result<InvokeOutput> {
        let output = run_command(&self.command, MAX_TOOL_RESPONSE_SIZE / 3, Some(output)).await?;
        let clean_stdout = sanitize_unicode_tags(&output.stdout);
        let clean_stderr = sanitize_unicode_tags(&output.stderr);

        let result = serde_json::json!({
            "exit_status": output.exit_status.unwrap_or(0).to_string(),
            "stdout": clean_stdout,
            "stderr": clean_stderr,
        });

        Ok(InvokeOutput {
            output: OutputKind::Json(result),
        })
    }

    pub fn queue_description(&self, output: &mut impl Write) -> Result<()> {
        queue!(output, style::Print("I will run the following shell command: "),)?;

        // TODO: Could use graphemes for a better heuristic
        if self.command.len() > 20 {
            queue!(output, style::Print("\n"),)?;
        }

        queue!(
            output,
            style::SetForegroundColor(Color::Green),
            style::Print(&self.command),
            style::Print("\n"),
            style::ResetColor
        )?;

        // Add the summary if available
        if let Some(ref summary) = self.summary {
            super::display_purpose(Some(summary), output)?;
        }

        queue!(output, style::Print("\n"))?;

        Ok(())
    }

    pub async fn validate(&mut self, _os: &Os) -> Result<()> {
        // TODO: probably some small amount of PATH checking
        Ok(())
    }

    pub fn eval_perm(&self, agent: &Agent) -> PermissionEvalResult {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Settings {
            #[serde(default)]
            allowed_commands: Vec<String>,
            #[serde(default)]
            denied_commands: Vec<String>,
            #[serde(default = "default_allow_read_only")]
            allow_read_only: bool,
        }

        fn default_allow_read_only() -> bool {
            true
        }

        let Self { command, .. } = self;
        let tool_name = if cfg!(windows) { "execute_cmd" } else { "execute_bash" };
        let is_in_allowlist = agent.allowed_tools.contains("execute_bash");
        
        // First check if there are specific tool settings
        if let Some(settings) = agent.tools_settings.get(tool_name) {
            let Settings {
                allowed_commands,
                denied_commands,
                allow_read_only,
            } = match serde_json::from_value::<Settings>(settings.clone()) {
                Ok(settings) => settings,
                Err(e) => {
                    error!("Failed to deserialize tool settings for execute_bash: {:?}", e);
                    return PermissionEvalResult::Ask;
                },
            };

            if denied_commands.iter().any(|dc| command.contains(dc)) {
                return PermissionEvalResult::Deny;
            }

            if self.requires_acceptance(Some(&allowed_commands), allow_read_only) {
                PermissionEvalResult::Ask
            } else {
                PermissionEvalResult::Allow
            }
        } else if is_in_allowlist {
            // Tool is in allowedTools but no specific settings
            PermissionEvalResult::Allow
        } else {
            // Default behavior - use read-only commands and prompt for others
            if self.requires_acceptance(None, default_allow_read_only()) {
                PermissionEvalResult::Ask
            } else {
                PermissionEvalResult::Allow
            }
        }
    }
}

pub struct CommandResult {
    pub exit_status: Option<i32>,
    /// Truncated stdout
    pub stdout: String,
    /// Truncated stderr
    pub stderr: String,
}

// Helper function to format command output with truncation
pub fn format_output(output: &str, max_size: usize) -> String {
    format!(
        "{}{}",
        truncate_safe(output, max_size),
        if output.len() > max_size { " ... truncated" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_requires_acceptance_for_readonly_commands() {
        let cmds = &[
            // Safe commands
            ("ls ~", false),
            ("ls -al ~", false),
            ("pwd", false),
            ("echo 'Hello, world!'", false),
            ("which aws", false),
            // Potentially dangerous readonly commands
            ("echo hi > myimportantfile", true),
            ("ls -al >myimportantfile", true),
            ("echo hi 2> myimportantfile", true),
            ("echo hi >> myimportantfile", true),
            ("echo $(rm myimportantfile)", true),
            ("echo `rm myimportantfile`", true),
            ("echo hello && rm myimportantfile", true),
            ("echo hello&&rm myimportantfile", true),
            ("ls nonexistantpath || rm myimportantfile", true),
            ("echo myimportantfile | xargs rm", true),
            ("echo myimportantfile|args rm", true),
            ("echo <(rm myimportantfile)", true),
            ("cat <<< 'some string here' > myimportantfile", true),
            ("echo '\n#!/usr/bin/env bash\necho hello\n' > myscript.sh", true),
            ("cat <<EOF > myimportantfile\nhello world\nEOF", true),
            // Safe piped commands
            ("find . -name '*.rs' | grep main", false),
            ("ls -la | grep .git", false),
            ("cat file.txt | grep pattern | head -n 5", false),
            // Unsafe piped commands
            ("find . -name '*.rs' | rm", true),
            ("ls -la | grep .git | rm -rf", true),
            ("echo hello | sudo rm -rf /", true),
            // `find` command arguments
            ("find important-dir/ -exec rm {} \\;", true),
            ("find . -name '*.c' -execdir gcc -o '{}.out' '{}' \\;", true),
            ("find important-dir/ -delete", true),
            (
                "echo y | find . -type f -maxdepth 1 -okdir open -a Calculator {} +",
                true,
            ),
            ("find important-dir/ -name '*.txt'", false),
            // `grep` command arguments
            ("echo 'test data' | grep -P '(?{system(\"date\")})'", true),
        ];
        for (cmd, expected) in cmds {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": cmd,
            }))
            .unwrap();
            assert_eq!(
                tool.requires_acceptance(None, true),
                *expected,
                "expected command: `{}` to have requires_acceptance: `{}`",
                cmd,
                expected
            );
        }
    }

    #[test]
    fn test_requires_acceptance_for_windows_commands() {
        let cmds = &[
            // Safe Windows commands
            ("dir", false),
            ("type file.txt", false),
            ("echo Hello, world!", false),
            // Potentially dangerous Windows commands
            ("del file.txt", true),
            ("rmdir /s /q folder", true),
            ("rd /s /q folder", true),
            ("format c:", true),
            ("erase file.txt", true),
            ("copy file.txt > important.txt", true),
            ("move file.txt destination", true),
            // Command with pipes
            ("dir | findstr txt", true),
            ("type file.txt | findstr pattern", true),
            // Dangerous piped commands
            ("dir | del", true),
            ("type file.txt | del", true),
        ];

        for (cmd, expected) in cmds {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": cmd,
            }))
            .unwrap();
            assert_eq!(
                tool.requires_acceptance(None, true),
                *expected,
                "expected command: `{}` to have requires_acceptance: `{}`",
                cmd,
                expected
            );
        }
    }

    #[test]
    fn test_wildcard_pattern_matching() {
        let test_cases = vec![
            // Test case: (command, allowed_patterns, allow_read_only, should_require_acceptance)
            
            // Exact string matching (backward compatibility)
            ("git status", vec!["git".to_string()], true, false),
            ("git status", vec!["ls".to_string()], true, true), // git is not read-only
            
            // Basic wildcard patterns
            ("git status", vec!["git*".to_string()], true, false),
            ("git commit -m 'test'", vec!["git*".to_string()], true, false),
            ("ls -la", vec!["git*".to_string()], true, false), // ls is read-only, so allowed
            ("rm file", vec!["git*".to_string()], true, true), // rm is not read-only and not in pattern
            
            // Specific command with wildcard
            ("git commit -m 'test'", vec!["git commit*".to_string()], true, false),
            ("git commit --amend", vec!["git commit*".to_string()], true, false),
            ("git status", vec!["git commit*".to_string()], true, true), // git status doesn't match git commit*
            
            // Multiple patterns
            ("git status", vec!["ls*".to_string(), "git*".to_string()], true, false),
            ("ls -la", vec!["ls*".to_string(), "git*".to_string()], true, false),
            ("rm file", vec!["ls*".to_string(), "git*".to_string()], true, true),
            
            // Complex patterns
            ("npm install package", vec!["npm install *".to_string()], true, false),
            ("npm run build", vec!["npm install *".to_string()], true, true),
            ("npm run test", vec!["npm run *".to_string()], true, false),
            
            // Mixed exact and wildcard patterns
            ("git status", vec!["ls".to_string(), "git*".to_string()], true, false),
            ("ls", vec!["ls".to_string(), "git*".to_string()], true, false),
            ("rm file", vec!["ls".to_string(), "git*".to_string()], true, true),
            
            // Edge cases
            ("git", vec!["git*".to_string()], true, false),
            ("g", vec!["git*".to_string()], true, true), // g is not read-only and doesn't match
            ("gitfoo", vec!["git*".to_string()], true, false), // This should match git*
            
            // Test with allow_read_only = false
            ("ls -la", vec!["git*".to_string()], false, true), // ls doesn't match pattern and read-only not allowed
            ("cat file", vec!["git*".to_string()], false, true), // cat doesn't match pattern and read-only not allowed
        ];

        for (command, allowed_patterns, allow_read_only, should_require_acceptance) in test_cases {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": command,
            }))
            .unwrap();
            
            let result = tool.requires_acceptance(Some(&allowed_patterns), allow_read_only);
            assert_eq!(
                result, should_require_acceptance,
                "Command '{}' with patterns {:?}, allow_read_only={} - expected requires_acceptance: {}, got: {}",
                command, allowed_patterns, allow_read_only, should_require_acceptance, result
            );
        }
    }

    #[test]
    fn test_command_matches_allowed_patterns() {
        // Test exact matching - first word
        assert!(ExecuteCommand::command_matches_allowed_patterns("git", "git status", &["git".to_string()]));
        assert!(!ExecuteCommand::command_matches_allowed_patterns("git", "git status", &["ls".to_string()]));

        // Test exact matching - full command
        assert!(ExecuteCommand::command_matches_allowed_patterns("cargo", "cargo check", &["cargo check".to_string()]));
        assert!(ExecuteCommand::command_matches_allowed_patterns("npm", "npm install package", &["npm install package".to_string()]));
        assert!(!ExecuteCommand::command_matches_allowed_patterns("cargo", "cargo build", &["cargo check".to_string()]));

        // Test wildcard matching
        assert!(ExecuteCommand::command_matches_allowed_patterns("git", "git status", &["git*".to_string()]));
        assert!(ExecuteCommand::command_matches_allowed_patterns("git", "git commit -m test", &["git*".to_string()]));
        assert!(!ExecuteCommand::command_matches_allowed_patterns("ls", "ls -la", &["git*".to_string()]));

        // Test specific command wildcards
        assert!(ExecuteCommand::command_matches_allowed_patterns("git", "git commit -m test", &["git commit*".to_string()]));
        assert!(!ExecuteCommand::command_matches_allowed_patterns("git", "git status", &["git commit*".to_string()]));

        // Test complex patterns
        assert!(ExecuteCommand::command_matches_allowed_patterns("npm", "npm install package", &["npm install *".to_string()]));
        assert!(!ExecuteCommand::command_matches_allowed_patterns("npm", "npm run test", &["npm install *".to_string()]));

        // Test invalid patterns (should fall back to exact matching)
        assert!(!ExecuteCommand::command_matches_allowed_patterns("git", "git status", &["[invalid".to_string()]));
    }

    #[test]
    fn test_wildcard_patterns_with_dangerous_commands() {
        // Even with wildcard patterns, dangerous commands should still be caught
        let dangerous_commands = vec![
            "rm -rf / && echo done", // && is dangerous
            "git status && rm important_file", // && is dangerous
            "echo $(rm file)", // $() is dangerous
        ];

        for cmd in dangerous_commands {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": cmd,
            }))
            .unwrap();
            
            // Even with very permissive wildcard patterns, dangerous commands should require acceptance
            let very_permissive_patterns = vec!["*".to_string(), "git*".to_string(), "rm*".to_string()];
            assert!(
                tool.requires_acceptance(Some(&very_permissive_patterns), true),
                "Dangerous command '{}' should require acceptance even with permissive patterns",
                cmd
            );
        }

        // Test piped commands - these should be handled differently
        // For piped commands, each command in the pipe is checked separately
        let piped_commands = vec![
            ("ls | rm", vec!["ls*".to_string()], true), // rm is not allowed
            ("ls | rm", vec!["ls*".to_string(), "rm*".to_string()], false), // both allowed
            ("cat file | grep pattern", vec!["cat*".to_string()], false), // grep is read-only
        ];

        for (cmd, patterns, should_require_acceptance) in piped_commands {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": cmd,
            }))
            .unwrap();
            
            let result = tool.requires_acceptance(Some(&patterns), true);
            assert_eq!(
                result, should_require_acceptance,
                "Piped command '{}' with patterns {:?} - expected requires_acceptance: {}, got: {}",
                cmd, patterns, should_require_acceptance, result
            );
        }
    }

    #[test]
    fn test_toolsettings_independent_of_allowedtools() {
        // Test that toolsSettings work even when execute_bash is NOT in allowedTools
        // Create agent through JSON deserialization to handle the complex types
        let agent_json = serde_json::json!({
            "name": "test_agent",
            "allowedTools": ["fs_read"], // execute_bash NOT included
            "toolsSettings": {
                "execute_bash": {
                    "allowedCommands": ["git*", "ls*"],
                    "allowReadOnly": true
                }
            }
        });
        
        let agent: crate::cli::agent::Agent = serde_json::from_value(agent_json).unwrap();

        let test_cases = vec![
            // Commands that should match patterns and be allowed
            ("git status", false),
            ("git commit -m test", false),
            ("ls -la", false),
            
            // Commands that don't match patterns but are read-only (should be allowed)
            ("cat file.txt", false),
            ("echo hello", false),
            
            // Commands that don't match patterns and aren't read-only (should require acceptance)
            ("rm file.txt", true),
            ("npm install", true),
        ];

        for (command, should_require_acceptance) in test_cases {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": command,
            }))
            .unwrap();
            
            let result = tool.eval_perm(&agent);
            let requires_acceptance = matches!(result, PermissionEvalResult::Ask);
            
            assert_eq!(
                requires_acceptance, should_require_acceptance,
                "Command '{}' - expected requires_acceptance: {}, got: {} (result: {:?})",
                command, should_require_acceptance, requires_acceptance, result
            );
        }
    }

    #[test]
    fn test_exact_full_command_matching_bug_fix() {
        // This test specifically covers the bug where "cargo check" was in allowedCommands
        // but still prompted for permission because we only compared against the first word "cargo"
        
        let test_cases = vec![
            // Test case: (command, allowed_patterns, should_require_acceptance)
            ("cargo check", vec!["cargo check".to_string()], false), // Should be allowed
            ("cargo build", vec!["cargo check".to_string()], true),  // Should require acceptance
            ("npm install package", vec!["npm install".to_string()], true), // Partial match, should require acceptance
            ("npm install", vec!["npm install".to_string()], false), // Exact match, should be allowed
            ("git commit -m test", vec!["git commit -m test".to_string()], false), // Exact full match
            ("git commit -m different", vec!["git commit -m test".to_string()], true), // Different, should require acceptance
        ];

        for (command, allowed_patterns, should_require_acceptance) in test_cases {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": command,
            }))
            .unwrap();
            
            let result = tool.requires_acceptance(Some(&allowed_patterns), true);
            assert_eq!(
                result, should_require_acceptance,
                "Command '{}' with patterns {:?} - expected requires_acceptance: {}, got: {}",
                command, allowed_patterns, should_require_acceptance, result
            );
        }
    }

    #[test]
    fn test_piped_commands_with_wildcards() {
        let test_cases = vec![
            // Safe piped commands with wildcards
            ("git log | grep commit", vec!["git*".to_string(), "grep*".to_string()], false),
            ("ls -la | grep .txt", vec!["ls*".to_string(), "grep*".to_string()], false),
            
            // Mixed allowed/disallowed in pipe
            ("git status | rm", vec!["git*".to_string()], true), // rm not allowed and not read-only
            ("ls | grep pattern", vec!["ls*".to_string()], false), // grep is read-only, so allowed
            
            // All commands in pipe allowed
            ("find . -name '*.rs' | grep main | head -5", 
             vec!["find*".to_string(), "grep*".to_string(), "head*".to_string()], false),
             
            // Test with read-only commands in pipe
            ("cat file | head -10", vec![], false), // both cat and head are read-only
            ("ls | sort", vec![], true), // ls is read-only but sort is not, and sort not in patterns
        ];

        for (command, allowed_patterns, should_require_acceptance) in test_cases {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": command,
            }))
            .unwrap();
            
            let result = tool.requires_acceptance(Some(&allowed_patterns), true);
            assert_eq!(
                result, should_require_acceptance,
                "Piped command '{}' with patterns {:?} - expected requires_acceptance: {}, got: {}",
                command, allowed_patterns, should_require_acceptance, result
            );
        }
    }

    #[test]
    fn test_requires_acceptance_allowed_commands() {
        let allowed_cmds: &[String] = &[
            String::from("git status"),
            String::from("root"),
            String::from("command subcommand a=[0-9]{10} b=[0-9]{10}"),
            String::from("command subcommand && command subcommand"),
        ];
        let cmds = &[
            // Command first argument 'root' allowed (allows all subcommands)
            ("root", false),
            ("root subcommand", true),
            // Valid allowed_command_regex matching
            ("git", true),
            ("git status", false),
            ("command subcommand a=0123456789 b=0123456789", false),
            ("command subcommand a=0123456789 b=012345678", true),
            ("command subcommand alternate a=0123456789 b=0123456789", true),
            // Control characters ignored due to direct allowed_command_regex match
            ("command subcommand && command subcommand", false),
        ];
        for (cmd, expected) in cmds {
            let tool = serde_json::from_value::<ExecuteCommand>(serde_json::json!({
                "command": cmd,
            }))
            .unwrap();
            assert_eq!(
                tool.requires_acceptance(Option::from(&allowed_cmds.to_vec()), true),
                *expected,
                "expected command: `{}` to have requires_acceptance: `{}`",
                cmd,
                expected
            );
        }
    }
}
