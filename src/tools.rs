use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use glib::{Bytes, clone};
use gtk4::prelude::*;
use image::EncodableLayout;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::rc::Rc;

#[derive(PartialEq, Eq)]
enum VaultReadState {
    Name,
    Index,
    Data,
}

pub fn hashify_sha256(data: &String) -> [u8; 32] {
    Sha256::digest(data.as_bytes()).into()
}

pub fn u8_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_u8(data: &String) -> Result<Vec<u8>, std::num::ParseIntError> {
    let mut resvec: Vec<u8> = Vec::new();
    for i in (0..data.len()).step_by(2) {
        if i == data.len() - 1 {
            eprintln!("hex2u8 conversion break occurred");
            break;
        }
        resvec.push(u8::from_str_radix(&data[i..i + 2], 16)?);
    }
    Ok(resvec)
}

pub fn show_alert(parent: &impl IsA<gtk4::Window>, title: &str, message: &str) {
    let dialog = gtk4::AlertDialog::builder()
        .message(title)
        .detail(message)
        .modal(true)
        .buttons(["OK"])
        .default_button(0)
        .build();
    dialog.choose(Some(parent), gtk4::gio::Cancellable::NONE, |_| {});
}

pub fn get_vault_path() -> Option<String> {
    let opath = get_vault_dir();
    if opath.is_none() {
        return None;
    }
    Some(format!("{}/master.vbase", opath.unwrap()))
}

pub fn get_vault_dir() -> Option<String> {
    let rapppath = std::env::current_exe();
    if rapppath.is_err() {
        return None;
    }
    let mut apppath = rapppath.unwrap();
    apppath.pop();
    let opath = apppath.to_str();
    if opath.is_none() {
        return None;
    }
    return Some(opath.unwrap().to_string());
}

pub fn get_pixbuf_with_embedded_image(img_buf: &[u8]) -> gtk4::gdk_pixbuf::Pixbuf {
    let raw_img = image::load_from_memory(img_buf).unwrap();
    let img = raw_img.to_rgba8();
    let (iheight, iwidth) = img.dimensions();

    gtk4::gdk_pixbuf::Pixbuf::from_bytes(
        &Bytes::from(img.as_bytes()),
        gtk4::gdk_pixbuf::Colorspace::Rgb,
        true,
        8,
        iwidth as i32,
        iheight as i32,
        (iwidth * 4) as i32,
    )
}

pub fn add_vault(
    master_data: String,
    vname: &String,
    password: String,
    mwindow: &impl IsA<gtk4::Window>,
) -> Option<(String, String)> {
    let vault_data = format!("^{vname}\n[Index]\n[Data]\n");
    let onewvault = encrypt_aes_with_key(mwindow, &vault_data, &hashify_sha256(&password));
    if onewvault.is_none() {
        return None;
    }
    let newvault = onewvault.unwrap();
    let added_vault = format!(
        "{}:{}{}\n",
        vname,
        u8_to_hex(&newvault.0),
        u8_to_hex(&newvault.1)
    );
    return Some((format!("{master_data}{added_vault}"), added_vault));
}

pub fn get_current_from_vault_path(
    file_list: Rc<gtk4::ListBox>,
    index: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    data: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    path: PathBuf,
    name_viewer: Rc<gtk4::Label>,
    content_viewer: Rc<gtk4::TextView>,
) -> Vec<gtk4::Button> {
    let mut items: Vec<gtk4::Button> = Vec::new();
    for (ipath, name) in &*index.borrow() {
        let name = name.clone();
        let ipath = Rc::new(ipath.clone());
        if !ipath.starts_with(&path) {
            continue;
        }
        // Exclude subdirectory here
        if ipath.parent().unwrap() != path {
            continue;
        }

        let fname = name + if ipath.ends_with("/") { "/" } else { "" };
        let lbutton = gtk4::Button::new();
        lbutton.add_css_class(&fname);
        let ltext = gtk4::Label::new(Some(&fname));
        ltext.set_width_chars(24);
        lbutton.set_child(Some(&ltext));

        let name_viewer_rc = Rc::clone(&name_viewer);
        let content_viewer_rc = Rc::clone(&content_viewer);
        if ipath.ends_with("/") {
            // Go down
            let rpath = path.clone();
            let flist_rc = Rc::clone(&file_list);
            let index_rc = Rc::clone(&index);
            let data_rc = Rc::clone(&data);
            lbutton.connect_clicked(move |_| {
                let mut newpath = rpath.clone();
                newpath.push(Rc::clone(&ipath).as_ref());
                loop {
                    let dwidget = match flist_rc.last_child() {
                        Some(w) => w,
                        None => break,
                    };
                    flist_rc.remove(&dwidget);
                }

                for button in get_current_from_vault_path(
                    Rc::clone(&flist_rc),
                    Rc::clone(&index_rc),
                    Rc::clone(&data_rc),
                    newpath,
                    Rc::clone(&name_viewer_rc),
                    Rc::clone(&content_viewer_rc),
                ) {
                    flist_rc.append(&button);
                }
            });
        } else {
            // Show file
            let vindex = Rc::clone(&index);
            let vdata = Rc::clone(&data);
            lbutton.connect_clicked(move |_| {
                for class in name_viewer_rc.css_classes() {
                    name_viewer_rc.remove_css_class(class.as_str());
                }
                let fileid_str = ipath.as_os_str().to_str().unwrap();
                let fileid = PathBuf::from(&fileid_str);
                let vf_index = vindex.borrow();
                let vf_data = vdata.borrow();
                let data = match vf_data.get(&fileid) {
                    Some(d) => d,
                    None => return,
                };
                let title = match vf_index.get(&fileid) {
                    Some(s) => s,
                    None => return,
                };
                let data_utf8 = str::from_utf8(data);
                if data_utf8.is_ok() {
                    name_viewer_rc.set_text(title);
                    content_viewer_rc.buffer().set_text(data_utf8.unwrap());
                } else {
                    name_viewer_rc.set_text(&(title.to_owned() + " : Binary"));
                    content_viewer_rc.buffer().set_text(&u8_to_hex(data));
                }
                name_viewer_rc.add_css_class(fileid_str);
                content_viewer_rc.set_editable(true);
            });
        }

        items.push(lbutton);
    }
    if path.to_str().unwrap() != "/" {
        let abutton = gtk4::Button::with_label("../");
        abutton.add_css_class("../");

        abutton.connect_clicked(move |_| {
            // Go up
            let newpath = path.parent().unwrap().to_path_buf();
            loop {
                let dwidget = match file_list.last_child() {
                    Some(w) => w,
                    None => break,
                };
                file_list.remove(&dwidget);
            }
            for button in get_current_from_vault_path(
                Rc::clone(&file_list),
                Rc::clone(&index),
                Rc::clone(&data),
                newpath,
                Rc::clone(&name_viewer),
                Rc::clone(&content_viewer),
            ) {
                file_list.append(&button);
            }
        });

        items.push(abutton);
    }
    items
}

pub fn vault_data_append(
    filepath: Rc<String>,
    filename: String,
    file_data: Option<Vec<u8>>,
    vindex: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    vdata: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
) {
    // Get file id here
    // Maybe I can just save next index
    let mut fileid: u16 = 0;
    loop {
        let filepath = format!("{}{}", Rc::clone(&filepath), fileid.to_string());
        if vindex.borrow().contains_key(&PathBuf::from(filepath)) {
            fileid += 1;
        } else {
            break;
        }
    }
    for itempath in vindex.borrow().values() {
        let lfilepath = Rc::clone(&filepath);
        if !itempath.starts_with(lfilepath.as_ref()) {
            continue;
        }
        if itempath == &PathBuf::from(format!("{lfilepath}{}", fileid.to_string())) {
            fileid += 1;
        } else {
            break;
        }
    }
    // Add file to index
    let file_pathcode = format!("{filepath}{fileid}");
    eprintln!("Filename:{filename}\nFileID:{fileid}\nFile pathcode: {file_pathcode}\n");
    vindex
        .borrow_mut()
        .insert(PathBuf::from(&file_pathcode), filename.to_string());
    // Also to data
    if file_data.is_none() {
        vdata
            .borrow_mut()
            .insert(PathBuf::from(file_pathcode), Vec::new());
    } else {
        vdata
            .borrow_mut()
            .insert(PathBuf::from(file_pathcode), file_data.unwrap());
    }
}

pub fn read_master(parent: &impl IsA<gtk4::Window>) -> Option<([u8; 1], [u8; 12], Vec<u8>)> {
    // Open file
    let ovaultpath = get_vault_path();
    if ovaultpath.is_none() {
        show_alert(
            parent,
            "Error",
            "Failed to detect the path to 'master.vbase'.",
        );
        return None;
    }
    let rbase_file = std::fs::File::open(&ovaultpath.unwrap());
    if rbase_file.is_err() {
        show_alert(
            parent,
            "Error",
            "Could not open 'master.vbase' in read_master.",
        );
        return None;
    }
    let mut base_file = rbase_file.unwrap();
    // Read data
    let mut type_buf = [0u8; 1];
    let rread_nonce = base_file.read_exact(&mut type_buf);
    if rread_nonce.is_err() {
        show_alert(
            parent,
            "Error",
            "Failed to read vault type from 'master.vbase'.",
        );
        return None;
    }
    let mut nonce_buf = [0u8; 12];
    let rread_nonce = base_file.read_exact(&mut nonce_buf);
    if rread_nonce.is_err() {
        show_alert(parent, "Error", "Failed to read nonce from 'master.vbase'.");
        return None;
    }
    let mut base_cipher: Vec<u8> = Vec::new();
    let rread_cipher = base_file.read_to_end(&mut base_cipher);
    if rread_cipher.is_err() {
        show_alert(parent, "Error", "Failed to read data from 'master.vbase'.");
        return None;
    }
    return Some((type_buf, nonce_buf, base_cipher));
}

pub fn write_master(
    parent: &impl IsA<gtk4::Window>,
    enctype: &[u8; 1],
    nonce: [u8; 12],
    data: Vec<u8>,
) {
    // Open tmp
    let ovaultpath = get_vault_dir();
    if ovaultpath.is_none() {
        show_alert(
            parent,
            "Error",
            "Failed to detect the directory of 'master.vbase'.",
        );
        return;
    }
    let vtmppath = ovaultpath.unwrap() + "/master.vbase.tmp";
    let rbase_file = std::fs::File::create(&vtmppath);
    if rbase_file.is_err() {
        show_alert(parent, "Error", "Could not create 'master.vbase.tmp'.");
        return;
    }
    let mut base_file = rbase_file.unwrap();
    // Write data to tmp
    let rwrite_type = base_file.write(enctype);
    if rwrite_type.is_err() {
        show_alert(
            parent,
            "Error",
            "Failed to write vault type to 'master.vbase.tmp'.",
        );
        return;
    }
    let rwrite_nonce = base_file.write(&nonce);
    if rwrite_nonce.is_err() {
        show_alert(
            parent,
            "Error",
            "Failed to write nonce to 'master.vbase.tmp'.",
        );
        return;
    }
    let rwrite_data = base_file.write(&data);
    if rwrite_data.is_err() {
        show_alert(
            parent,
            "Error",
            "Failed to write vault data to 'master.vbase.tmp'.",
        );
        return;
    }
    let rwrite_flush = base_file.flush();
    if rwrite_flush.is_err() {
        show_alert(parent, "Error", "Failed to flush output stream.");
        return;
    }
    // Copy
    let rcopy = std::fs::copy(&vtmppath, get_vault_path().unwrap());
    if rcopy.is_err() {
        show_alert(
            parent,
            "Error",
            "Failed to copy 'master.vbase.tmp' to 'master.vbase'.\nTry renaming 'master.vbase.tmp' to 'master.vbase' manually.",
        );
        return;
    }
    if rcopy.unwrap() != 13 + data.len() as u64 {
        show_alert(
            parent,
            "Alert",
            "Failed to copy 'master.vbase.tmp' to 'master.vbase'.\nThe vault data may be corrupted.",
        );
    }
    // Remove tmp
    let rdelete = std::fs::remove_file(vtmppath);
    if rdelete.is_err() {
        show_alert(
            parent,
            "Alert",
            "Failed to delete 'master.vbase.tmp'.\nTry deleteing 'master.vbase.tmp' manually.",
        );
    }
    return;
}

pub fn vault_decode(
    vault_data: &String,
) -> Option<(
    String,
    BTreeMap<PathBuf, String>,
    BTreeMap<PathBuf, Vec<u8>>,
)> {
    let mut read_state = VaultReadState::Name;
    let mut vname: String = "Invalid^".to_string();
    let mut vindex: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut vdata: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    for line in vault_data.split("\n") {
        if line.starts_with("^") {
            vname = line[1..].to_string();
            continue;
        } else if read_state == VaultReadState::Name && line == "[Index]" {
            read_state = VaultReadState::Index;
            continue;
        } else if read_state == VaultReadState::Index && line == "[Data]" {
            read_state = VaultReadState::Data;
            continue;
        }

        if read_state == VaultReadState::Index {
            if !line.contains(":") {
                continue;
            }
            let (dir, name) = line.split_once(":").unwrap();
            if dir.ends_with("/") {
                // It's a directory!
                vindex.insert(PathBuf::from(dir), format!("{name}/"));
            } else {
                vindex.insert(PathBuf::from(dir), name.to_string());
            }
        } else if read_state == VaultReadState::Data {
            if !line.contains(":") {
                continue;
            }
            let (dir, data) = line.split_once(":").unwrap();
            vdata.insert(PathBuf::from(dir), hex_to_u8(&data.to_string()).unwrap());
        }
    }
    if &vname == "Invalid^" {
        return None;
    }
    return Some((vname, vindex, vdata));
}

pub fn encrypt_aes(parent: &impl IsA<gtk4::Window>, value: &str) -> Option<([u8; 12], Vec<u8>)> {
    encrypt_aes_with_key(parent, value, BASE_KEY)
}

pub fn encrypt_aes_with_key(
    parent: &impl IsA<gtk4::Window>,
    value: &str,
    key: &[u8; 32],
) -> Option<([u8; 12], Vec<u8>)> {
    // Encrypt default value
    let rcipher = Aes256Gcm::new_from_slice(key);
    if rcipher.is_err() {
        show_alert(
            parent,
            "Error",
            "Failed to initialize encryption. Aborting.",
        );
        return None;
    }
    let cipher = rcipher.unwrap();
    let mut rng = OsRng::default();
    let mut nonce_ary: [u8; 12] = Default::default();
    let rnonce = rng.try_fill_bytes(&mut nonce_ary);
    if rnonce.is_err() {
        show_alert(parent, "Error", "Failed to generate nonce. Aborting.");
        return None;
    }
    let nonce = Nonce::from_slice(&nonce_ary);

    let rencrypted = cipher.encrypt(nonce, value.as_bytes());
    if rencrypted.is_err() {
        show_alert(parent, "Error", "Failed to encrypt default data. Aborting.");
        return None;
    }
    Some((nonce_ary, rencrypted.unwrap()))
}

pub fn decrypt_aes(
    parent: &impl IsA<gtk4::Window>,
    ciphertext: &Vec<u8>,
    nonce_buf: [u8; 12],
    show_error: bool,
) -> Option<Vec<u8>> {
    decrypt_aes_with_key(parent, ciphertext, nonce_buf, BASE_KEY, show_error)
}

pub fn decrypt_aes_with_key(
    parent: &impl IsA<gtk4::Window>,
    ciphertext: &[u8],
    nonce_buf: [u8; 12],
    key: &[u8; 32],
    show_error: bool,
) -> Option<Vec<u8>> {
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new_from_slice(aes_key).unwrap();
    let nonce = Nonce::from_slice(&nonce_buf);
    let rbase_data = cipher.decrypt(nonce, ciphertext);
    if rbase_data.is_err() {
        if show_error == true {
            show_alert(parent, "Error", "Error: Failed to decrypt provided data.");
        }
        return None;
    }
    return Some(rbase_data.unwrap());
}

pub fn delete_button_vault_list(
    base_string: Rc<String>,
    capp: &gtk4::Application,
    commlabel: Rc<gtk4::Label>,
) -> Vec<gtk4::Button> {
    let mut buttons: Vec<gtk4::Button> = Vec::new();
    for line in base_string.split("\n") {
        if line.starts_with("^") {
            continue;
        }
        if let Some((mvid, mvhex)) = line.split_once(":") {
            let mvname = Rc::new(mvid.to_string());
            let mvdata = Rc::new(mvhex.to_string());
            let vlist_button = gtk4::Button::with_label(&mvname);
            let base_string_l = Rc::clone(&base_string);
            let commlabel_l = Rc::clone(&commlabel);
            vlist_button.connect_clicked(clone!(
                #[weak]
                capp,
                move |_| {
                    // Ask vault password
                    let pw_window = gtk4::Window::builder()
                        .title("Unlock vault")
                        .modal(true)
                        .build();
                    pw_window.set_application(Some(&capp));

                    let pw_grid = gtk4::Grid::builder()
                        .margin_top(6)
                        .margin_bottom(6)
                        .margin_start(12)
                        .margin_end(12)
                        .row_spacing(24)
                        .column_spacing(12)
                        .build();

                    // Password label
                    let pw_pass_label = gtk4::Label::new(Some("Enter Vault password to confirm:"));
                    pw_grid.attach(&pw_pass_label, 1, 1, 1, 1);
                    // Password input box
                    let pw_pass_box = gtk4::PasswordEntry::new();
                    pw_pass_box.set_size_request(100, 24);
                    pw_grid.attach(&pw_pass_box, 1, 2, 1, 1);
                    // Confirm button
                    let pw_ok_button = gtk4::Button::with_label("OK");
                    let vname = Rc::clone(&mvname);
                    let vdata = Rc::clone(&mvdata);
                    let base_string_clone = Rc::clone(&base_string_l);
                    let c_label = Rc::clone(&commlabel_l);

                    pw_ok_button.connect_clicked(clone!(
                        #[weak]
                        pw_window,
                        move |_| {
                            // Decode
                            let ovault_raw = decrypt_aes_with_key(
                                &pw_window,
                                &hex_to_u8(&Rc::clone(&vdata)).unwrap()[12..],
                                hex_to_u8(&Rc::clone(&vdata)).unwrap()[0..12]
                                    .try_into()
                                    .unwrap(),
                                &hashify_sha256(&pw_pass_box.text().to_string()),
                                false,
                            );
                            if ovault_raw.is_none() {
                                show_alert(&pw_window, "Alert", "Vault decryption failed.\nThe password is incorrect, or the vault is broken.");
                                return;
                            }
                            // Remove selected one
                            let mut deleted_base = String::new();
                            for dline in base_string_clone.split("\n") {
                                if !dline.starts_with(&format!("{}:", Rc::clone(&vname))) {
                                    deleted_base = format!("{deleted_base}{dline}\n");
                                }
                            }
                            let label = c_label.as_ref();
                            label.set_text(&deleted_base);
                            label.add_css_class(&format!("notify_{}", Rc::clone(&vname)));

                            pw_window.close();
                        }
                    ));
                    pw_grid.attach(&pw_ok_button, 2, 2, 1, 1);

                    pw_window.set_child(Some(&pw_grid));
                    pw_window.present();
                }
            ));
            buttons.push(vlist_button);
        }
    }
    buttons
}

pub fn filebase_setup(
    application: &gtk4::Application,
    window: Rc<gtk4::ApplicationWindow>,
    base_file: fs::File,
    vault_path: Rc<String>,
) {
    // Setup window
    let setup_window = gtk4::Window::builder()
        .application(application)
        .title("FileBase setup")
        .resizable(false)
        .modal(true)
        .build();
    setup_window.set_size_request(400, 480);

    let setup_grid = gtk4::Grid::builder()
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .row_spacing(8)
        .column_spacing(8)
        .build();

    let setup_title = gtk4::Label::new(Some("Welcome to FileBase!"));
    setup_title.add_css_class("big");
    setup_grid.attach(&setup_title, 1, 1, 2, 1);

    let setup_desc = gtk4::Label::new(Some(
        "FileBase will help keep your files safe.\nRead PRECAUTIONS before start!",
    ));
    setup_grid.attach(&setup_desc, 1, 2, 2, 1);

    // Read before continue
    let setup_precautions = gtk4::ScrolledWindow::new();
    setup_precautions.set_hscrollbar_policy(gtk4::PolicyType::Never);
    setup_precautions.add_css_class("notice");
    setup_precautions.set_size_request(320, 280);
    let setup_precautions_text = gtk4::Label::builder()
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .wrap(true)
        .wrap_mode(gtk4::pango::WrapMode::Word)
        .build();
    setup_precautions_text.set_label(PRECAUTIONS_TXT);
    setup_precautions_text.add_css_class("notice");
    setup_precautions.set_child(Some(&setup_precautions_text));
    setup_grid.attach(&setup_precautions, 1, 3, 2, 1);

    // Master file encryption selectors etc.
    let setup_aes_desc = gtk4::Label::new(Some("Select master file encryption:"));
    setup_grid.attach(&setup_aes_desc, 1, 4, 2, 1);

    let setup_aes_selector1r = gtk4::CheckButton::with_label("Use defalt");
    let setup_aes_selector2r = gtk4::CheckButton::with_label("Use password (extra safety)");
    setup_aes_selector1r.set_group(Some(&setup_aes_selector2r));

    setup_grid.attach(&setup_aes_selector1r, 1, 5, 1, 1);
    setup_grid.attach(&setup_aes_selector2r, 2, 5, 1, 1);
    let setup_aes_selector1 = Rc::new(setup_aes_selector1r);
    let setup_aes_selector2 = Rc::new(setup_aes_selector2r);

    let setup_aes_pwbox = gtk4::PasswordEntry::new();
    setup_aes_pwbox.set_placeholder_text(Some("Enter Master password here..."));
    setup_grid.attach(&setup_aes_pwbox, 2, 6, 1, 1);

    let setup_aes_button = gtk4::Button::with_label("OK");
    let masterfile = RefCell::new(base_file);
    let setup_aes_sel1 = Rc::clone(&setup_aes_selector1);
    let setup_aes_sel2 = Rc::clone(&setup_aes_selector2);
    setup_aes_button.connect_clicked(clone!(
        #[weak]
        setup_window,
        move |_| {
            let default_encrypt = setup_aes_sel1.is_active();
            if default_encrypt || setup_aes_sel2.is_active() {
                // Use default encryption
                let oencrypted = if default_encrypt {
                    encrypt_aes(&setup_window, "^FileBase All-in-One vault Ver.1^\n")
                } else {
                    encrypt_aes_with_key(
                        &setup_window,
                        "^FileBase All-in-One vault Ver.1^\n",
                        &hashify_sha256(&(setup_aes_pwbox.text().to_string() + MASTER_KEY_SALT)),
                    )
                };
                if oencrypted.is_none() {
                    return;
                }
                let (nonced, valued) = oencrypted.unwrap();
                let mut mfile = masterfile.borrow_mut();

                let rtwrite = mfile.write(if default_encrypt { b"d" } else { b"u" });
                if rtwrite.is_err() {
                    show_alert(
                        &setup_window,
                        "Error",
                        "Could not write encrypt type to master vault.",
                    );
                    return;
                }
                let rnwrite = mfile.write_all(&nonced);
                if rnwrite.is_err() {
                    show_alert(
                        &setup_window,
                        "Error",
                        "Could not write nonce to master vault.",
                    );
                    return;
                }
                let rdwrite = mfile.write_all(&valued);
                if rdwrite.is_err() {
                    show_alert(
                        &setup_window,
                        "Error",
                        "Could not write default value to master vault.",
                    );
                    return;
                }
                setup_window.add_css_class("init_complete");
                setup_window.close();
            }
        }
    ));
    setup_grid.attach(&setup_aes_button, 2, 7, 1, 1);

    setup_window.set_child(Some(&setup_grid));
    setup_window.connect_close_request(move |swindow| {
        if !swindow.has_css_class("init_complete") {
            let _ = fs::remove_file(vault_path.as_ref());
            window.close();
        };
        glib::Propagation::Proceed
    });
    setup_window.present();
}

pub const MASTER_KEY_SALT: &str = ":MKS#QW50aS1kaWN0aW9uYXJ5";

// CBK: Common Base Key
const BASE_KEY: &[u8; 32] = b"CBK@TmV2ZXJHb25uYUdpdmVZb3VVcA==";

const PRECAUTIONS_TXT: &str = concat!(
    "1. DATA INTEGRITY\n",
    "THIS DOES NOT GUARANTEE THAT ENCRYPTED DATA HAS NOT BEEN ALTERED. DATA TAMPERING OR CORRUPTION MAY OCCUR.\n\n",
    "2. DATA LEGALITY\n",
    "USERS ARE SOLELY RESPONSIBLE FOR VERIFYING AND ENSURING THAT THE DATA THEY COLLECT, USE, AND STORE IS LEGALLY PERMISSIBLE. THIS PROGRAM DOES NOT ASSIST WITH SUCH COMPLIANCE.\n\n",
    "3. ACCESS CONTROL\n",
    "ENCRYPTION ALONE DOESN'T GUARANTEE SECURITY. PROPER ACCESS MANAGEMENT MUST BE IMPLEMENTED.\n\n",
    "4. KEY MANAGEMENT\n",
    "SECURELY MANAGING ENCRYPTION KEYS IS CRITICALLY IMPORTANT. IF A KEY IS COMPROMISED, DATA CONFIDENTIALITY WILL BE LOST.\n\n",
    "5. DATA RECOVERY IMPOSSIBILITY\n",
    "LOSING AN ENCRYPTION KEY WILL MAKE YOUR ENCRYPTED DATA INACCESSIBLE. SINCE IT CANNOT BE RECOVERED, THIS POSES A SIGNIFICANT RISK FOR IMPORTANT DATA.\n\n",
    "6. USER AGREEMENT\n",
    "USERS MUST ACKNOWLEDGE AND ACCEPT THE RISKS ASSOCIATED WITH USING THIS PROGRAM IN ADVANCE."
);
