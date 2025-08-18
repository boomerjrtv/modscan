# Gemini CLI Policy on File Deletion

This document outlines the strict policy for file deletion when interacting with the Gemini CLI agent. This policy is designed to ensure data integrity, prevent accidental loss of work, and maintain user trust.

## Core Principles:

1.  **No Unilateral Deletion:** The Gemini CLI agent will **never** delete any files without explicit, unambiguous user confirmation.
2.  **Explicit Confirmation Required:** For any proposed file deletion, the agent **must** present the user with a clear list of files to be deleted and await a direct "yes" or "confirm" from the user.
3.  **Automatic Backup:** Prior to any confirmed deletion, the Gemini CLI agent will automatically create a dated backup of the file(s) intended for deletion.
    *   **Backup Naming Convention:** Backup files will be named using the original filename followed by a timestamp in `YYYYMMDD_HHMMSS` format and a `.bak` extension (e.g., `original_file.py.20250817_143000.bak`).
    *   **Backup Location:** Backup files will be stored in a designated `gemini_backups/` directory within the project root. If this directory does not exist, the agent will create it.
4.  **Deletion Log:** All deleted files, along with their original path and the timestamp of deletion, will be logged in a file named `geminideleted.txt` located in the project root.

## Procedure for File Deletion:

1.  **User Request/Agent Proposal:** The process begins either with a direct user request to delete files or an agent proposal for cleanup.
2.  **List of Files:** The agent will present a clear, itemized list of all files proposed for deletion.
3.  **Confirmation Prompt:** The agent will explicitly ask the user for confirmation, stating the implications of deletion.
4.  **Backup Creation:** Upon user confirmation, the agent will first create dated backups of all files on the deletion list in the `gemini_backups/` directory.
5.  **File Deletion:** After successful backup, the agent will proceed with the deletion of the original files.
6.  **Log Entry:** An entry will be added to `geminideleted.txt` for each deleted file.
7.  **Confirmation of Action:** The agent will inform the user that the deletion process is complete and that backups have been created.

This policy is a commitment to safeguarding your work and ensuring a transparent and trustworthy interaction with the Gemini CLI agent.
