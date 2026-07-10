#[cfg(feature = "lang_en")]
pub mod text {
    pub mod generic {
        pub const ALERT: &str = "Alert";
        pub const ERROR: &str = "Error";
        pub const MAST_PW_TITLE: &str = "Master password";
        pub const MAST_PW_DESC: &str = "Enter password to open the master vault.";
        pub const VNAME_DECRYPTION_FAILED: &str = "Failed to decrypt 'vname'.";
        pub const VNAME_PARSE_FAILED: &str = "Could not parse 'vname' as string.";
        pub const MAST_ENCRYPTION_FAILED: &str = "Failed to encrypt master vault.";
        pub const MAST_LOCK_FAILED: &str = "Failed to acquire a lock on the master vault.\nAborting due to unreliable file access.";
        pub const MAST_TMP_LOCK_FAILED: &str = "Failed to acquire a lock on the BaseAES temporary file.\nAborting due to unreliable file access.";
    }

    pub mod home {
        pub const INFO_TITLE: &str = "About BaseAES";
        pub const INFO_DESC: &str = concat!(
            "BaseAES is a simple filesystem-like\n",
            "  vault system with strong encryption.\n\n",
            "Developed by @7654jp\n\n",
            "This software is licensed under the\n",
            "  version 3 of the GNU General Public License.\n",
            "For details, see LICENSE file in the repository."
        );
        pub const INFO_VIEW_REPO: &str = "View repository (GitHub)";

        pub const GET_DISPLAY_FAILED: &str = "Failed to get display.\nStylesheet is disabled.";
        pub const MAST_LOCATION_DESC: &str = "Master vault:";
        pub const MAST_LOCATION_PH: &str = "(Failed to retrieve the default path)";
        pub const MAST_LOCATION_CHANGE: &str = "Change";
        pub const MAST_LOCATION_SELECT: &str = "Select from file";
        pub const MAST_LOCATION_SELECT_TITLE: &str = "Select the master vault";
        pub const MAST_LOCATION_CREATE: &str = "Create new master vault";
        pub const ADD_NEW_VAULT: &str = "Add a Vault";
        pub const ADD_VAULT_NAME: &str = "Vault Name:";
        pub const ADD_VAULT_PW: &str = "Vault Password:";
        pub const ADD_NAME_CHARERR: &str = "Vault name cannot contain  ' ^ '  or  ' , '  .";
        pub const ADD_GENERATE_FAILED: &str = "Failed to generate the new vault.";
        pub const ADD_VNAME_ENC_FAILED: &str = "Failed to encrypt new 'vname'.";
        pub const ADD_VAULT_PARSE_FAILED: &str = "Could not parse vault data.";
        pub const OPEN_VAULT: &str = "Open a Vault";
        pub const OPEN_TITLE: &str = "Select a Vault to open:";
        pub const DELETE_VAULT: &str = "Delete a Vault";
        pub const DELETE_TITLE: &str = "Select a Vault to delete:";
        pub const DELETE_COMP_TITLE: &str = "Vault deletion complete";
        pub const DELETE_COMP_DESC: &str = "The selected vault has been deleted.";
    }

    pub mod unlock {
        pub const VUNLOCK_TITLE: &str = "Unlock Vault";
        pub const VUNLOCK_DEC_FAILED: &str =
            "Vault decryption failed.\nThe password is incorrect, or the Vault is broken.";
        pub const VUNLOCK_PARSE_FAILED: &str =
            "Could not parse decrypted vault data.\nThe Vault may be broken.";
        pub const VUNLOCK_SORRY: &str = "Sorry";
        pub const VUNLOCK_LOAD_NOT_FINISHED: &str =
            "Vault data loading is not finished.\nPlease try again in a few seconds.";
        pub const VUNLOCK_DISCONNECTED: &str =
            "Failed to load vault data. Close this 'Unlock vault' window and try again.";
    }

    pub mod explorer {
        pub const EXP_ITEMNAME_PH: &str = "Click the file to open...";
        pub const EXP_SAVE_ITEM: &str = "Save";
        pub const EXP_SHOW_FINFO: &str = "File info";
        pub const EXP_NEW_FILE: &str = "New file";
        pub const EXP_CREATE_FILE: &str = "Create file";
        pub const EXP_CREATE_TITLE: &str = "Create a new file";
        pub const EXP_CREATE_DESC: &str = "Enter file name:";
        pub const EXP_IMPORT_FILE: &str = "Import file";
        pub const EXP_IMPORT_TITLE: &str = "Select file to import...";
        pub const EXP_IMPORT_OPEN_ERROR: &str = "Failed to open the selected file.";
        pub const EXP_IMPORT_NAME_INVALID: &str =
            "The name of the selected file is invalid for this app.";
        pub const EXP_IMPORT_DUPLICATED_NAME: &str = " (Copy)";
        pub const EXP_IMPORT_BASE64: &str = "Import from Base64";
        pub const EXP_IMPORT_BASE64_DESC: &str = "Enter Base64 below:";
        pub const EXP_IMPORT_BASE64_EX: &str = "This prompt support:\nRaw Base64 (E.g. TmV2ZXJHb25uYUdpdmVZb3VVcA==)\n'data' URI (E.g. data:image/jpeg;base64,/9j/2wCEAAgGBgcGBQgH...)";
        pub const EXP_IMPORT_BASE64_INVALID: &str = "Failed to parse Base64 text.";
        pub const EXP_NEW_FOLDER: &str = "New folder";
        pub const EXP_NEW_FOLDER_TITLE: &str = "Add a new folder...";
        pub const EXP_NEW_FOLDER_DESC: &str = "Enter folder name:";
        pub const EXP_FOLDERNAME_DUPLICATED: &str = "The folder name cannot be the same.";
        pub const EXP_RENAME_ITEM: &str = "Rename";
        pub const EXP_RENAME_NOSEL: &str =
            "No file is selected.\nSelect a file you want to rename and try again.";
        pub const EXP_RENAME_TITLE: &str = "Rename item...";
        pub const EXP_RENAME_DESC1: &str = "Rename '";
        pub const EXP_RENAME_DESC2: &str = "' to:";
        pub const EXP_RENAME_NOTFOUND: &str = "Failed to find the selected item.";
        pub const EXP_MORE_CTRL: &str = "More...";
        pub const EXP_MOVE_ITEM: &str = "Move item";
        pub const EXP_MOVE_SEL_TITLE: &str = "Select what to move...";
        pub const EXP_MOVE_SEL_FILE: &str = "Move file";
        pub const EXP_MOVE_SEL_DIR: &str = "Move directory";
        pub const EXP_RELOAD_DIR: &str = "Reload";
        pub const EXP_EXPORT_ITEM: &str = "Export file";
        pub const EXP_EXPORT_NOSEL: &str =
            "No file is selected.\nSelect a file you want to export, then try again.";
        pub const EXP_EXPORT_TITLE: &str = "Export to...";
        pub const EXP_EXPORT_GET_DATA_FAILED: &str = "Failed to get the data of the selected file.";
        pub const EXP_EXPORT_WRITE_FAILED: &str = "Failed to export the selected file.";
        pub const EXP_EXPORT_FLUSH_FAILED: &str = "Failed to flush the output stream.";
        pub const EXP_DELETE_ITEM: &str = "Delete item";
        pub const EXP_DELETE_SEL_TITLE: &str = "Select what to delete...";
        pub const EXP_DELETE_SEL_FILE: &str = "Delete file";
        pub const EXP_DELETE_SEL_DIR: &str = "Delete directory";
        pub const EXP_DELETE_CONFIRM: &str = "Confirm deletion?";
        pub const EXP_DELETE_DIR_FETCH_FAILED: &str = "Failed to get the name of current folder.";
        pub const EXP_DELETE_DIR_DESC1: &str = "Are you sure you want to delete\nthe folder '";
        pub const EXP_DELETE_DIR_DESC2: &str = "' and everything inside?";
        pub const EXP_DELETE_NO_BTN: &str = "No";
        pub const EXP_DELETE_YES_BTN: &str = "Yes";
        pub const EXP_CLOSURE_TITLE: &str = "Save file changes?";
        pub const EXP_CLOSURE_DESC1: &str = "Do you want to save changes in '";
        pub const EXP_CLOSURE_DESC2: &str = "' ?";
        pub const EXP_DONTSAVE_ITEM: &str = "Don't save";
        pub const EXP_CLOSURE_CANCEL: &str = "Cancel";
        pub const EXP_DISCARD_TITLE: &str = "Discard changes?";
        pub const EXP_DISCARD_DESC: &str =
            "There are unsaved changes.\nIf you continue, all changes will be lost.";
        pub const EXP_DISCARD_CONT: &str = "Continue";
        pub const EXP_DISCARD_CANCEL: &str = "Cancel";
        pub const EXP_MOVE_NOSEL: &str =
            "No file is selected.\nSelect a file you want to move and try again.";
        pub const EXP_MOVE_TITLE: &str = "Move to...";
        pub const EXP_MOVE_CONFIRM: &str = "Move";
        pub const EXP_MOVE_FINFO_ERR: &str = "Failed to get the file information.";
        pub const EXP_MOVE_FDATA_ERR: &str = "Failed to get the file data.";
        pub const EXP_BGSF_STYLE_ERR: &str = "\nWarning: Invalid styling at line ";
        pub const EXP_BGSF_FORMAT_ERR: &str = "\nWarning: invalid format at line ";
        pub const EXP_BGSF_IMG_TYPE_SRY: &str = "Sorry, only PNG/JPEG Images are supported.";
        pub const EXP_CONTENT_BIN_TITLE: &str = "  :  Binary";
        pub const EXP_CONTENT_BIN_DESC: &str =
            "Viewing/Editing binary file will be implemented someday.";
    }

    pub mod setup {
        pub const WELCOME_TITLE: &str = "BaseAES Setup";
        pub const WELCOME_BASEAES: &str = "Welcome to BaseAES!";
        pub const WELCOME_DESC: &str =
            "BaseAES will help keep your files safe.\nRead PRECAUTIONS before start!";
        pub const PRECAUTIONS_TEXT: &str = concat!(
            "1. DATA INTEGRITY\n",
            "THIS DOES NOT GUARANTEE THAT ENCRYPTED DATA HAS NOT BEEN ALTERED. DATA TAMPERING OR CORRUPTION MAY OCCUR.\n\n",
            "2. DATA LEGALITY\n",
            "USERS ARE SOLELY RESPONSIBLE FOR VERIFYING AND ENSURING THAT ENCRYPTION AND THE DATA THEY COLLECT, USE, AND STORE IS LEGALLY PERMISSIBLE. THIS PROGRAM IS NOT INTENDED TO ENCOURAGE SUCH ILLEGAL ACTIVITIES.\n\n",
            "3. ACCESS CONTROL\n",
            "ENCRYPTION ALONE DOESN'T GUARANTEE SECURITY. PROPER ACCESS MANAGEMENT MUST BE IMPLEMENTED.\n\n",
            "4. KEY MANAGEMENT\n",
            "SECURELY MANAGING ENCRYPTION KEYS IS CRITICALLY IMPORTANT. IF A KEY IS COMPROMISED, DATA CONFIDENTIALITY WILL BE LOST.\n\n",
            "5. DATA RECOVERY IMPOSSIBILITY\n",
            "LOSING AN ENCRYPTION KEY WILL MAKE YOUR ENCRYPTED DATA INACCESSIBLE. SINCE IT CANNOT BE RECOVERED, THIS IS A SIGNIFICANT RISK FOR IMPORTANT DATA.\n\n",
            "6. USER AGREEMENT\n",
            "USERS MUST ACKNOWLEDGE AND ACCEPT THE RISKS ASSOCIATED WITH USING THIS PROGRAM IN ADVANCE.\n\n\n",
            "IF YOU AGREE TO THE PRECAUTIONS ABOVE, Enter the number '66550' below to complete the setup."
        );
        pub const WELCOME_MASTER_WILL_BE: &str = "Master vault will be saved at:";
        pub const WELCOME_MASTER_DEFAULT: &str = "Default location";
        pub const WELCOME_MASTER_OTHER: &str = "Other place";
        pub const WELCOME_MASTER_SELECT: &str = "Select...";
        pub const WELCOME_MASTER_SELECT_TITLE: &str = "Select where to save the master vault";
        pub const WELCOME_MASTER_ERROR: &str = "Failed to open the file.";
        pub const WELCOME_ENCRYPT_DESC: &str = "Select master vault encryption:";
        pub const WELCOME_ENCRYPT_DEFAULT: &str = "Use included key (weaker)";
        pub const WELCOME_ENCRYPT_USERPW: &str = "Use password (recommended)";
        pub const WELCOME_ENCRYPT_PWPH: &str = "Enter Master password here...";
        pub const WELCOME_ALREADY_DONE: &str = "I already have the master vault";
        pub const WELCOME_CONFIRM_PH: &str = "Enter confirm code here";
        pub const SETUP_ERROR_NOENCTYPE: &str = "Please select the encryption type.";
        pub const SETUP_ERROR_CONFIRM_MISMATCH: &str = "Read PRECAUTIONS and enter the correct code.\nMake sure that the number is entered correctly.";
        pub const SETUP_ERROR_EMPTY_PW: &str = "Master password cannot be empty.";
        pub const SETUP_ERROR_EMPTY_LOCATION: &str =
            "Please select where to save the master vault.";
        pub const SETUP_ERROR_LOCATION_FETCH_FAILED: &str =
            "Failed to get the location to save the master vault.";
        pub const SETUP_ERROR_CREATE_NEW_FAILED: &str =
            "Failed to create the new master vault.\nBaseAES does not support overwriting.";
        pub const SETUP_INIT_VNAME_ENC_FAILED: &str =
            "Failed to initialize vault.\n('vname' encryption failed)";
        pub const SETUP_INIT_VTYPE_BUFWRITE_FAILED: &str =
            "Failed to initialize vault.\n('vtype' bufwrite failed)";
        pub const SETUP_INIT_VNNONCE_BUFWRITE_FAILED: &str =
            "Failed to initialize vault.\n('vname-nonce' bufwrite failed)";
        pub const SETUP_INIT_VNCLEN_BUFWRITE_FAILED: &str =
            "Failed to initialize vault.\n('vname-cipher-length' bufwrite failed)";
        pub const SETUP_INIT_VNCIPHER_BUFWRITE_FAILED: &str =
            "Failed to initialize vault.\n('vname-cipher' bufwrite failed)";
        pub const SETUP_INIT_BUFFER_FLUSH_FAILED: &str =
            "Failed to initialize vault.\n(Buffer flush failed)";
    }

    pub mod tools {
        pub const VNAME_CHECK_CORRUPTED: &str = "The vault index is corrupted.";
        pub const VNAME_CHECK_DUPLICATED: &str = "The vault name cannot be the same.";
        pub const FILENAME_ILLEGAL_CHARS: &str =
            "File name cannot contain \"^\" or \":\" or \"/\" or \"'\" .";
        pub const FILENAME_FIRST_WAS_SPACE: &str = "File name cannot start with ' '.";
        pub const FILENAME_ILLEGAL_ENDING: &str = "File name cannot end with ' ' or '.'.";
        pub const FILENAME_EMPTY: &str = "File name cannot be empty.";
        pub const FILENAME_DUPLICATED: &str = "The file name cannot be the same.";
        pub const DIRNAME_ILLEGAL_CHARS: &str =
            "Folder name cannot contain \"^\" or \":\" or \"/\" or \"'\" .";
        pub const DIRNAME_FIRST_WAS_SPACE: &str = "Folder name cannot start with ' '.";
        pub const DIRNAME_ILLEGAL_ENDING: &str = "Folder name cannot end with ' ' or '.'.";
        pub const DIRNAME_EMPTY: &str = "Folder name cannot be empty.";
        pub const BGSF_NOFILE: &str = "\nWarning: The file doesn't exist at line ";
        pub const BGSF_TEXT_PARSE_FAILED: &str =
            "Failed to read data as text. Data does exist but we're not able to show it.";
        pub const BGSF_PATH_ERR: &str = "\nWarning: Invalid path at line ";
        pub const OPEN_MAST_FAILED: &str = "Failed to open the master vault.";
        pub const AES_ENCRYPT_INIT_FAILED: &str = "Failed to initialize encryption. Aborting.";
        pub const AES_ENCRYPT_NONCEGEN_FAILED: &str = "Failed to generate nonce. Aborting.";
        pub const AES_ENCRYPT_EXEC_FAILED: &str = "Failed to encrypt the given data.";
        pub const AES_DECRYPT_EXEC_FAILED: &str = "Failed to decrypt the given data.";
        pub const READ_MAST_VINFO_FAILED: &str =
            "Failed to read 'vname-info' from the master vault.";
        pub const READ_MAST_VNAME_FAILED: &str =
            "Failed to read 'vname-cipher' from the master vault.";
        pub const READ_MAST_VNAME_SEEK_FAILED: &str = "Failed to seek for 'vname-cipher'.";
        pub const READ_MAST_VDLEN_SKIP_FAILED: &str =
            "Failed to read 'vdata-length' to skip from the master vault.";
        pub const READ_MAST_VDLEN_SEEK_FAILED: &str = "Failed to seek for 'vdata' to skip.";
        pub const READ_MAST_VDINFO_FAILED: &str =
            "Failed to read 'vdata-info' from the master vault.";
        pub const READ_MAST_VDATA_FAILED: &str =
            "Failed to read 'vdata-cipher' from the master vault.";
        pub const UPDATE_MAST_OPEN_TMP_FAILED: &str = "Could not create a temp file.\nPlease rename the '(master vault name).tmp' and try again.";
        pub const UPDATE_MAST_VTYPE_BUFWRITE_FAILED: &str =
            "Failed to write 'vtype' to the output buffer.";
        pub const UPDATE_MAST_VNNONCE_BUFWRITE_FAILED: &str =
            "Failed to write 'vname-nonce' to the output buffer.";
        pub const UPDATE_MAST_VNLEN_BUFWRITE_FAILED: &str =
            "Failed to write 'vname-length' to the output buffer.";
        pub const UPDATE_MAST_VNAME_BUFWRITE_FAILED: &str =
            "Failed to write 'vname-cipher' to the output buffer.";
        pub const UPDATE_MAST_VINFO_SEEK_FAILED: &str = "Failed to seek for old 'vname-info'.";
        pub const UPDATE_MAST_VNLEN_READ_FAILED: &str =
            "Failed to read old 'vname-length' from the master vault.";
        pub const UPDATE_MAST_VNAME_SEEK_FAILED: &str = "Failed to seek for old 'vname-cipher'.";
        pub const UPDATE_MAST_VINFO_COPY_FAILED: &str = "Failed to read 'vname-info' to be copied.";
        pub const UPDATE_MAST_VINFO_BUFWRITE_FAILED: &str =
            "Failed to write 'vname-info' to the output buffer.";
        pub const UPDATE_MAST_VNAME_COPY_FAILED: &str =
            "Failed to read 'vname-cipher' to be copied.";
        pub const DELETE_VAULT_CONF_TITLE: &str = "Confirm deletion";
        pub const DELETE_VAULT_CONF_DESC: &str = "Enter Vault password to confirm:";
        pub const MAST_VAULT_DEC_FAILED: &str = "Failed to decrypt master vault.";
        pub const MAST_VAULT_UDEC_FAILED: &str =
            "Failed to decrypt master vault.\nThe password might be incorrect.";
        pub const SAVE_VAULT_TITLE: &str = "Save changes?";
        pub const SAVE_VAULT_DESC1: &str = "Do you want to save change(s) in the Vault '";
        pub const SAVE_VAULT_DESC2: &str = "' ?";
        pub const EXP_DELETE_NOSEL: &str =
            "No file is selected.\nSelect a file you want to delete, and try again.";
        pub const EXP_DELETE_FILE_DESC1: &str = "Are you sure you want to delete '";
        pub const EXP_DELETE_FILE_DESC2: &str = "' ?";
        pub const EXP_DELETE_NOT_FOUND: &str = "The selected file was not found.";
        pub const EXP_DELETE_INDEX_NF: &str =
            "The index of the file was not found, but the deletion of its data was successful.";
        pub const EXP_DELETE_DATA_NF: &str =
            "The index of the file is deleted, but failed to find its data.";
    }
}

#[cfg(feature = "lang_ja")]
pub mod text {
    pub mod generic {
        pub const ALERT: &str = "注意";
        pub const ERROR: &str = "エラー";
        pub const MAST_PW_TITLE: &str = "マスターパスワード";
        pub const MAST_PW_DESC: &str =
            "マスター金庫を開けるためにマスターパスワードを入力してください。";
        pub const VNAME_DECRYPTION_FAILED: &str = "'vname'の復号に失敗しました。";
        pub const VNAME_PARSE_FAILED: &str = "'vname'の文字列への変換に失敗しました。";
        pub const MAST_ENCRYPTION_FAILED: &str = "マスター金庫の暗号化に失敗しました。";
        pub const MAST_LOCK_FAILED: &str = "マスター金庫のロック取得に失敗しました。\nファイルアクセスが不安定なためタスクを中止しました。";
        pub const MAST_TMP_LOCK_FAILED: &str = "マスター金庫の一時ファイルのロック取得に失敗しました。\nファイルアクセスが不安定なためタスクを中止しました。";
    }

    pub mod home {
        pub const INFO_TITLE: &str = "BaseAESについて";
        pub const INFO_DESC: &str = concat!(
            "BaseAESは強力な暗号化機能を持った\n",
            "  Vault ファイルシステムです。\n\n",
            "開発者: @7654jp\n\n",
            "このソフトウェアは the version 3 of the\n",
            "  GNU General Public Licenseのもとで\n",
            "  ライセンスされています。\n",
            "詳しくはリポジトリ内のLICENSEファイルを\n",
            "  参照してください。"
        );
        pub const INFO_VIEW_REPO: &str = "リポジトリを見る (GitHub)";

        pub const GET_DISPLAY_FAILED: &str =
            "表示ディスプレイの取得に失敗しました。\nスタイルシートは無効化されました。";
        pub const MAST_LOCATION_DESC: &str = "マスター金庫:";
        pub const MAST_LOCATION_PH: &str = "(マスター金庫のデフォルト場所の取得に失敗しました)";
        pub const MAST_LOCATION_CHANGE: &str = "変更";
        pub const MAST_LOCATION_SELECT: &str = "ファイルから選択";
        pub const MAST_LOCATION_SELECT_TITLE: &str = "マスター金庫を選択してください";
        pub const MAST_LOCATION_CREATE: &str = "新しいマスター金庫を作成";
        pub const ADD_NEW_VAULT: &str = "Vaultを作成";
        pub const ADD_VAULT_NAME: &str = "Vault名:";
        pub const ADD_VAULT_PW: &str = "パスワード:";
        pub const ADD_NAME_CHARERR: &str = "Vault名が  ' ^ '  や  ' , '  を含むことはできません。";
        pub const ADD_GENERATE_FAILED: &str = "新しいVaultの生成に失敗しました。";
        pub const ADD_VNAME_ENC_FAILED: &str = "変更された'vname'の暗号化に失敗しました。";
        pub const ADD_VAULT_PARSE_FAILED: &str = "Vaultのデータを読み取れませんでした。";
        pub const OPEN_VAULT: &str = "Vaultを開く";
        pub const OPEN_TITLE: &str = "開きたいVaultを選択:";
        pub const DELETE_VAULT: &str = "Vaultを削除";
        pub const DELETE_TITLE: &str = "削除したいVaultを選択:";
        pub const DELETE_COMP_TITLE: &str = "Vaultの削除完了";
        pub const DELETE_COMP_DESC: &str = "選択されたVaultの削除が実行されました。";
    }

    pub mod unlock {
        pub const VUNLOCK_TITLE: &str = "Vaultをアンロック";
        pub const VUNLOCK_DEC_FAILED: &str =
            "Vaultの復号に失敗しました。\nパスワードが間違っているか、Vaultが破損しています。";
        pub const VUNLOCK_PARSE_FAILED: &str =
            "復号したVaultのデータを変換できませんでした。\nVaultが破損している可能性があります。";
        pub const VUNLOCK_SORRY: &str = "すみません";
        pub const VUNLOCK_LOAD_NOT_FINISHED: &str =
            "Vaultデータの読み込みが完了していません。\n数秒後にやり直してください。";
        pub const VUNLOCK_DISCONNECTED: &str = "Vaultデータの読み込みに失敗しました。\n'Vaultをアンロック'の画面を閉じてやり直してください。";
    }

    pub mod explorer {
        pub const EXP_ITEMNAME_PH: &str = "ファイルを選択して開く";
        pub const EXP_SAVE_ITEM: &str = "保存";
        pub const EXP_SHOW_FINFO: &str = "ファイル情報";
        pub const EXP_NEW_FILE: &str = "新規ファイル";
        pub const EXP_CREATE_FILE: &str = "ファイルを作成";
        pub const EXP_CREATE_TITLE: &str = "新しいファイルを作成";
        pub const EXP_CREATE_DESC: &str = "ファイル名を入力:";
        pub const EXP_IMPORT_FILE: &str = "インポート";
        pub const EXP_IMPORT_TITLE: &str = "インポートするファイルを選択してください";
        pub const EXP_IMPORT_OPEN_ERROR: &str = "選択されたファイルを開けませんでした。";
        pub const EXP_IMPORT_NAME_INVALID: &str =
            "選択されたファイルの名前はこのアプリでは無効です。";
        pub const EXP_IMPORT_DUPLICATED_NAME: &str = " (コピー)";
        pub const EXP_IMPORT_BASE64: &str = "Base64から";
        pub const EXP_IMPORT_BASE64_DESC: &str = "Base64を下の欄に入力してください:";
        pub const EXP_IMPORT_BASE64_EX: &str = "このプロンプトでは、\nBase64単体 (例: TmV2ZXJHb25uYUdpdmVZb3VVcA==)\n'data' URI (例: data:image/jpeg;base64,/9j/2wCEAAgGBgcGBQgH...)\nがサポートされます。";
        pub const EXP_IMPORT_BASE64_INVALID: &str = "Base64テキストの読み取りに失敗しました。";
        pub const EXP_NEW_FOLDER: &str = "新規フォルダ";
        pub const EXP_NEW_FOLDER_TITLE: &str = "新しいフォルダーを作成";
        pub const EXP_NEW_FOLDER_DESC: &str = "フォルダー名を入力:";
        pub const EXP_FOLDERNAME_DUPLICATED: &str = "フォルダ名は同一にできません。";
        pub const EXP_RENAME_ITEM: &str = "名前を変更";
        pub const EXP_RENAME_NOSEL: &str = "ファイルが選択されていません。\n名前を変更したいファイルを選んでからもう一度試してください。";
        pub const EXP_RENAME_TITLE: &str = "名前を変更する";
        pub const EXP_RENAME_DESC1: &str = "'";
        pub const EXP_RENAME_DESC2: &str = "' の名前を変更:";
        pub const EXP_RENAME_NOTFOUND: &str = "選択されたファイルが見つかりませんでした。";
        pub const EXP_MORE_CTRL: &str = "その他";
        pub const EXP_MOVE_ITEM: &str = "ファイルを移動";
        pub const EXP_MOVE_SEL_TITLE: &str = "移動するものを選択する";
        pub const EXP_MOVE_SEL_FILE: &str = "ファイルを移動";
        pub const EXP_MOVE_SEL_DIR: &str = "フォルダーを移動";
        pub const EXP_RELOAD_DIR: &str = "再読み込み";
        pub const EXP_EXPORT_ITEM: &str = "エクスポート";
        pub const EXP_EXPORT_NOSEL: &str = "ファイルが選択されていません。\nエクスポートしたいファイルを選んでからもう一度試してください。";
        pub const EXP_EXPORT_TITLE: &str = "エクスポート先を選択する";
        pub const EXP_EXPORT_GET_DATA_FAILED: &str =
            "選択されたファイルのデータを取得できませんでした。";
        pub const EXP_EXPORT_WRITE_FAILED: &str =
            "選択されたファイルのエクスポートに失敗しました。";
        pub const EXP_EXPORT_FLUSH_FAILED: &str = "出力ストリームのフラッシュに失敗しました。";
        pub const EXP_DELETE_ITEM: &str = "アイテムの削除";
        pub const EXP_DELETE_SEL_TITLE: &str = "削除するものを選択する";
        pub const EXP_DELETE_SEL_FILE: &str = "ファイルを削除";
        pub const EXP_DELETE_SEL_DIR: &str = "フォルダーを削除";
        pub const EXP_DELETE_CONFIRM: &str = "本当に削除しますか？";
        pub const EXP_DELETE_DIR_FETCH_FAILED: &str = "フォルダー名の取得に失敗しました。";
        pub const EXP_DELETE_DIR_DESC1: &str = "本当に '";
        pub const EXP_DELETE_DIR_DESC2: &str =
            "' フォルダーと\n中のすべての項目を削除したいですか？";
        pub const EXP_DELETE_NO_BTN: &str = "いいえ";
        pub const EXP_DELETE_YES_BTN: &str = "はい";
        pub const EXP_CLOSURE_TITLE: &str = "変更を保存しますか？";
        pub const EXP_CLOSURE_DESC1: &str = "'";
        pub const EXP_CLOSURE_DESC2: &str = "'の変更を保存しますか？";
        pub const EXP_DONTSAVE_ITEM: &str = "保存しない";
        pub const EXP_CLOSURE_CANCEL: &str = "キャンセル";
        pub const EXP_DISCARD_TITLE: &str = "変更を破棄しますか？";
        pub const EXP_DISCARD_DESC: &str =
            "保存されていない変更があります。\nこのまま続けた場合、変更は全て破棄されます。";
        pub const EXP_DISCARD_CONT: &str = "続ける";
        pub const EXP_DISCARD_CANCEL: &str = "キャンセル";
        pub const EXP_MOVE_NOSEL: &str = "ファイルが選択されていません。\n移動したいファイルを選んでからもう一度試してください。";
        pub const EXP_MOVE_TITLE: &str = "移動する";
        pub const EXP_MOVE_CONFIRM: &str = "移動";
        pub const EXP_MOVE_FINFO_ERR: &str = "ファイル情報の取得に失敗しました。";
        pub const EXP_MOVE_FDATA_ERR: &str = "ファイルデータの取得に失敗しました。";
        pub const EXP_BGSF_STYLE_ERR: &str = "\n警告: 無効なスタイリングがあります。行 ";
        pub const EXP_BGSF_FORMAT_ERR: &str = "\n警告: 無効なフォーマットがあります。行 ";
        pub const EXP_BGSF_IMG_TYPE_SRY: &str =
            "すみません、PNGとJPEG画像しかサポートしていません。";
        pub const EXP_CONTENT_BIN_TITLE: &str = "  :  バイナリ";
        pub const EXP_CONTENT_BIN_DESC: &str =
            "バイナリファイルの閲覧・編集機能はいつか実装されます。";
    }

    pub mod setup {
        pub const WELCOME_TITLE: &str = "BaseAES セットアップ";
        pub const WELCOME_BASEAES: &str = "BaseAESへようこそ！";
        pub const WELCOME_DESC: &str = "BaseAESであなたのファイルを安全に保ちましょう。\n使用前の注意を読んでから使ってください！";
        pub const PRECAUTIONS_TEXT: &str = concat!(
            "1. データ完全性\n",
            "このアプリケーション（以下、アプリ）は暗号化されたデータが改変されていないことを保証するものではありません。 データの改ざんや破損が発生する可能性があります。\n\n",
            "2. データの合法性\n",
            "このアプリの利用者は暗号化の行為や取得、利用、保存するデータが法律に違反しないことを自己の責任で確認する必要があります。 このアプリにはその行為について一切加担する意図はありません。\n\n",
            "3. アクセス管理\n",
            "暗号化だけでは安全を保証できません。 適切なアクセス管理も導入される必要があります。\n\n",
            "4. 暗号化キー管理\n",
            "暗号化キーを安全に管理することが極めて重要です。 暗号化キーが漏洩した場合、データの機密性は失われます。\n\n",
            "5. データ復元の不可能性\n",
            "暗号化キーを失うと暗号化されたデータにアクセスすることが出来なくなります。 復元方法は存在しないため、これは重要なデータを保存する目的には大きなリスクとなります。\n\n",
            "6. ユーザー同意\n",
            "利用者はこのアプリを使用する際に発生するリスクを理解し、許容しなければなりません。\n\n\n",
            "以上の使用前の注意に同意する場合、'66550'を下の欄に入力してセットアップを完了してください。"
        );
        pub const WELCOME_MASTER_WILL_BE: &str = "マスター金庫の保存先は:";
        pub const WELCOME_MASTER_DEFAULT: &str = "デフォルトの場所";
        pub const WELCOME_MASTER_OTHER: &str = "その他の場所";
        pub const WELCOME_MASTER_SELECT: &str = "選択...";
        pub const WELCOME_MASTER_SELECT_TITLE: &str = "マスター金庫の保存先を選択:";
        pub const WELCOME_MASTER_ERROR: &str = "ファイルを開けませんでした。";
        pub const WELCOME_ENCRYPT_DESC: &str = "マスター金庫の暗号化方法を選択:";
        pub const WELCOME_ENCRYPT_DEFAULT: &str = "プログラム内蔵キーを使用（弱い）";
        pub const WELCOME_ENCRYPT_USERPW: &str = "マスターパスワードを使用（推奨）";
        pub const WELCOME_ENCRYPT_PWPH: &str = "マスターパスワードをここに入力...";
        pub const WELCOME_ALREADY_DONE: &str = "すでにマスター金庫があります";
        pub const WELCOME_CONFIRM_PH: &str = "確認コードをここに入力";
        pub const SETUP_ERROR_NOENCTYPE: &str = "マスター金庫の暗号化方法を選択してください。";
        pub const SETUP_ERROR_CONFIRM_MISMATCH: &str = "使用前の注意を読んで、確認コードを入力してください。\n確認コードが正しいこと、半角で入力されていることを確認してください。"; // If this comment is removed, the zed scrollbar doesn't work
        pub const SETUP_ERROR_EMPTY_PW: &str = "マスターパスワードは空白にできません。";
        pub const SETUP_ERROR_EMPTY_LOCATION: &str = "マスター金庫の保存先を選択してください。";
        pub const SETUP_ERROR_LOCATION_FETCH_FAILED: &str =
            "マスター金庫の保存先の取得に失敗しました。";
        pub const SETUP_ERROR_CREATE_NEW_FAILED: &str =
            "マスター金庫の新規作成に失敗しました。\nBaseAESでは既存の金庫の上書きはできません。";
        pub const SETUP_INIT_VNAME_ENC_FAILED: &str =
            "マスター金庫のセットアップに失敗しました。\n('vname' encryption failed)";
        pub const SETUP_INIT_VTYPE_BUFWRITE_FAILED: &str =
            "マスター金庫のセットアップに失敗しました。\n('vtype' bufwrite failed)";
        pub const SETUP_INIT_VNNONCE_BUFWRITE_FAILED: &str =
            "マスター金庫のセットアップに失敗しました。\n('vname-nonce' bufwrite failed)";
        pub const SETUP_INIT_VNCLEN_BUFWRITE_FAILED: &str =
            "マスター金庫のセットアップに失敗しました。\n('vname-cipher-length' bufwrite failed)";
        pub const SETUP_INIT_VNCIPHER_BUFWRITE_FAILED: &str =
            "マスター金庫のセットアップに失敗しました。\n('vname-cipher' bufwrite failed)";
        pub const SETUP_INIT_BUFFER_FLUSH_FAILED: &str =
            "マスター金庫のセットアップに失敗しました。\n(Buffer flush failed)";
    }

    pub mod tools {
        pub const VNAME_CHECK_CORRUPTED: &str = "Vaultのインデックスが破損しています。";
        pub const VNAME_CHECK_DUPLICATED: &str = "Vault名は重複することができません。";
        pub const FILENAME_ILLEGAL_CHARS: &str =
            "ファイル名に \"^\" か \":\" か \"/\" か \"'\" を含むことはできません。";
        pub const FILENAME_FIRST_WAS_SPACE: &str = "ファイル名は ' ' で始まることはできません。";
        pub const FILENAME_ILLEGAL_ENDING: &str =
            "ファイル名は ' ' か '.' で終わることはできません。";
        pub const FILENAME_EMPTY: &str = "ファイル名は空にできません。";
        pub const FILENAME_DUPLICATED: &str = "ファイル名は重複することができません。";
        pub const DIRNAME_ILLEGAL_CHARS: &str =
            "フォルダー名に \"^\" か \":\" か \"/\" か \"'\" を含むことはできません。";
        pub const DIRNAME_FIRST_WAS_SPACE: &str = "フォルダー名は ' ' で始まることはできません。";
        pub const DIRNAME_ILLEGAL_ENDING: &str =
            "フォルダー名は ' ' か '.' で終わることはできません。";
        pub const DIRNAME_EMPTY: &str = "フォルダー名は空にできません。";
        pub const BGSF_NOFILE: &str = "\n警告: 指定されたファイルは存在しません。行 ";
        pub const BGSF_TEXT_PARSE_FAILED: &str = "データをテキストとして読み込めませんでした。 データは存在しますが表示できませんでした。";
        pub const BGSF_PATH_ERR: &str = "\n警告: 無効なパスがあります。行 ";
        pub const OPEN_MAST_FAILED: &str = "マスター金庫を開けませんでした。";
        pub const AES_ENCRYPT_INIT_FAILED: &str =
            "暗号化のセットアップに失敗しました。タスクは中止されました。";
        pub const AES_ENCRYPT_NONCEGEN_FAILED: &str =
            "Nonce値の取得に失敗しました。タスクは中止されました。";
        pub const AES_ENCRYPT_EXEC_FAILED: &str = "提供されたデータの暗号化に失敗しました。";
        pub const AES_DECRYPT_EXEC_FAILED: &str = "提供されたデータの復号に失敗しました。";
        pub const READ_MAST_VINFO_FAILED: &str =
            "'vname-info'をマスター金庫から読み込めませんでした。";
        pub const READ_MAST_VNAME_FAILED: &str =
            "'vname-cipher'をマスター金庫から読み込めませんでした。";
        pub const READ_MAST_VNAME_SEEK_FAILED: &str = "'vname-cipher'のシークに失敗しました。";
        pub const READ_MAST_VDLEN_SKIP_FAILED: &str =
            "スキップ用の'vdata-length'をマスター金庫から読み込めませんでした。";
        pub const READ_MAST_VDLEN_SEEK_FAILED: &str = "スキップ用の'vdata'のシークに失敗しました。";
        pub const READ_MAST_VDINFO_FAILED: &str =
            "'vdata-info'をマスター金庫から読み込めませんでした。";
        pub const READ_MAST_VDATA_FAILED: &str =
            "'vdata-cipher'をマスター金庫から読み込めませんでした。";
        pub const UPDATE_MAST_OPEN_TMP_FAILED: &str = "一時ファイルの新規作成に失敗しました。\n'(マスター金庫のファイル名).tmp'というファイルの名前を変更してもう一度お試しください。";
        pub const UPDATE_MAST_VTYPE_BUFWRITE_FAILED: &str =
            "'vtype'を出力バッファに書き込めませんでした。";
        pub const UPDATE_MAST_VNNONCE_BUFWRITE_FAILED: &str =
            "'vname-nonce'を出力バッファに書き込めませんでした。";
        pub const UPDATE_MAST_VNLEN_BUFWRITE_FAILED: &str =
            "'vname-length'を出力バッファに書き込めませんでした。";
        pub const UPDATE_MAST_VNAME_BUFWRITE_FAILED: &str =
            "'vname-cipher'を出力バッファに書き込めませんでした。";
        pub const UPDATE_MAST_VINFO_SEEK_FAILED: &str =
            "保存前の'vname-info'のシークに失敗しました。";
        pub const UPDATE_MAST_VNLEN_READ_FAILED: &str =
            "保存前の'vname-length'の読み取りに失敗しました。";
        pub const UPDATE_MAST_VNAME_SEEK_FAILED: &str =
            "保存前の'vname-cipher'のシークに失敗しました。";
        pub const UPDATE_MAST_VINFO_COPY_FAILED: &str = "'vname-info'の読み取りに失敗しました。";
        pub const UPDATE_MAST_VINFO_BUFWRITE_FAILED: &str =
            "'vname-info'を出力バッファに書き込めませんでした。";
        pub const UPDATE_MAST_VNAME_COPY_FAILED: &str = "'vname-cipher'の読み取りに失敗しました。";
        pub const DELETE_VAULT_CONF_TITLE: &str = "削除の確認";
        pub const DELETE_VAULT_CONF_DESC: &str = "Vaultのパスワードを入力して承認してください:";
        pub const MAST_VAULT_DEC_FAILED: &str = "マスター金庫の復号に失敗しました。";
        pub const MAST_VAULT_UDEC_FAILED: &str =
            "マスター金庫の復号に失敗しました。\nパスワードが間違っている可能性があります。";
        pub const SAVE_VAULT_TITLE: &str = "変更を保存しますか？";
        pub const SAVE_VAULT_DESC1: &str = "Vault '";
        pub const SAVE_VAULT_DESC2: &str = "' での変更を保存しますか？";
        pub const EXP_DELETE_NOSEL: &str = "ファイルが選択されていません。\n削除したいファイルを選んでからもう一度試してください。";
        pub const EXP_DELETE_FILE_DESC1: &str = "本当に '";
        pub const EXP_DELETE_FILE_DESC2: &str = "' を削除しますか？";
        pub const EXP_DELETE_NOT_FOUND: &str = "選択されたファイルが見つかりませんでした。";
        pub const EXP_DELETE_INDEX_NF: &str =
            "ファイルのインデックスは見つかりませんでしたが、データの削除は成功しました。";
        pub const EXP_DELETE_DATA_NF: &str =
            "ファイルのインデックスは見つかりましたが、データの削除に失敗しました。";
    }
}
