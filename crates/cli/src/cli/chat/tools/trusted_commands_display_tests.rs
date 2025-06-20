use crate::cli::chat::tools::trusted_commands_config::locate_config_file;
use crate::platform::Context;

/// Tests that verify the display of trusted commands in the UI
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::chat::tools::execute_bash::ExecuteBash;

    /// Test that a command trusted by user configuration is displayed correctly
    #[tokio::test]
    async fn test_trusted_by_user_config_display() {
        // Create a test context
        let ctx = Context::builder().with_test_home().await.unwrap().build_fake();
        
        // Create a test configuration file
        let config_path = locate_config_file(&ctx);
        let dir_path = config_path.parent().unwrap();
        ctx.fs().create_dir_all(dir_path).await.unwrap();
        
        // Create a configuration that trusts "git status"
        let valid_json = r#"{
            "trusted_commands": [
                {
                    "type": "match",
                    "command": "git status",
                    "description": "Git status command"
                }
            ]
        }"#;
        
        ctx.fs().write(&config_path, valid_json).await.unwrap();
        
        // Create an ExecuteBash tool with the trusted command
        let execute_bash = ExecuteBash {
            command: "git status".to_string(),
            summary: None,
        };
        
        // Verify that the command requires acceptance (it's not a read-only command)
        assert!(execute_bash.requires_acceptance());
        
        // Verify that the command is trusted by user configuration
        assert!(execute_bash.check_trusted_command(&ctx).await);
        
        // TODO: In a real test, we would need to capture the output and verify
        // that "(trusted by user configuration)" is displayed. However, this would
        // require significant changes to the chat flow to make it testable.
        // For now, we'll just verify the logic that determines if a command
        // is trusted by user configuration.
    }

    /// Test that a command with dangerous patterns is never trusted, even if it matches
    /// a pattern in the trusted commands configuration
    #[tokio::test]
    async fn test_dangerous_command_never_trusted() {
        // Create a test context
        let ctx = Context::builder().with_test_home().await.unwrap().build_fake();
        
        // Create a test configuration file
        let config_path = locate_config_file(&ctx);
        let dir_path = config_path.parent().unwrap();
        ctx.fs().create_dir_all(dir_path).await.unwrap();
        
        // Create a configuration that trusts "npm" commands
        let valid_json = r#"{
            "trusted_commands": [
                {
                    "type": "match",
                    "command": "npm *",
                    "description": "All npm commands"
                }
            ]
        }"#;
        
        ctx.fs().write(&config_path, valid_json).await.unwrap();
        
        // Create an ExecuteBash tool with a dangerous command that matches the pattern
        let execute_bash = ExecuteBash {
            command: "npm run build > output.txt".to_string(),
            summary: None,
        };
        
        // Verify that the command requires acceptance
        assert!(execute_bash.requires_acceptance());
        
        // Verify that the command is NOT trusted, even though it matches the pattern
        assert!(!execute_bash.check_trusted_command(&ctx).await);
    }
}