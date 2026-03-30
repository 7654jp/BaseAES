/*
 * FileBase, a simple filesystem-like vault system with strong encryption.
 *   Copyright (C) 2026  @7654jp on GitHub
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use glib::clone;
use gtk4::gdk;
use gtk4::prelude::*;
use std::fs;
use std::rc::Rc;

mod tools;
use tools::*;
mod types;
mod vault;

fn open_main(application: &gtk4::Application) {
    // Main window
    let window = Rc::new(gtk4::ApplicationWindow::new(application));
    window.set_title(Some("FileBase"));
    window.set_default_size(400, 180);
    window.set_resizable(false);

    // Main grid
    let grid = gtk4::Grid::builder()
        .margin_top(6)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .row_spacing(24)
        .column_spacing(12)
        .build();

    // title label
    let title_label = gtk4::Label::new(None);
    title_label.set_markup("<b>FileBase Vault Manager</b>");
    title_label.add_css_class("big");
    grid.attach(&title_label, 1, 1, 3, 1);

    // Enable CSS
    let display = gdk::Display::default().expect("Error: Could not get default display.");
    let provider = gtk4::CssProvider::new();
    provider.load_from_data(include_str!("fstyle.css"));
    gtk4::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // Add vault button
    let add_button = gtk4::Button::new();
    add_button.set_size_request(120, 96);
    // Inside Add button
    let abbox = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    let abimg = gtk4::Image::new();
    abimg.set_size_request(48, 48);
    abimg.set_from_pixbuf(Some(&get_pixbuf_with_embedded_image(include_bytes!(
        "images/add.png"
    ))));
    abbox.append(&abimg);
    let ablabel = gtk4::Label::new(Some("Add new vault"));
    abbox.append(&ablabel);
    add_button.set_child(Some(&abbox));
    // Inline function
    let awindow = Rc::clone(&window);
    add_button.connect_clicked(clone!(
        #[weak]
        application,
        move |_| {
            // Create window and box
            let nv_window = gtk4::Window::new();
            nv_window.set_application(Some(&application));
            nv_window.set_title(Some("Add new vault..."));
            let nv_grid = gtk4::Grid::builder()
                .margin_top(8)
                .margin_bottom(8)
                .margin_start(8)
                .margin_end(8)
                .row_spacing(8)
                .column_spacing(8)
                .build();

            // Name label
            let nv_name_label = gtk4::Label::new(Some("Vault Name:"));
            nv_grid.attach(&nv_name_label, 1, 1, 2, 1);
            // Name input box
            let nv_name_box = gtk4::Entry::new();
            nv_name_box.set_size_request(120, 24);
            nv_grid.attach(&nv_name_box, 3, 1, 2, 1);
            // Password label
            let nv_pass_label = gtk4::Label::new(Some("Vault Password:"));
            nv_grid.attach(&nv_pass_label, 1, 2, 2, 1);
            // Password input box
            let nv_pass_boxr = gtk4::PasswordEntry::new();
            nv_pass_boxr.set_size_request(120, 24);
            nv_grid.attach(&nv_pass_boxr, 3, 2, 2, 1);
            let nv_pass_box = Rc::new(nv_pass_boxr);

            let nv_ok_button = gtk4::Button::with_label("OK");
            let aawindow = Rc::clone(&awindow);
            let nv_passbox_rc = Rc::clone(&nv_pass_box);
            nv_ok_button.connect_clicked(clone!(
                #[weak]
                application,
                #[weak]
                nv_window,
                move |_| {
                    // Filter vault name
                    let vname = Rc::new(nv_name_box.text().to_string());
                    if vname.contains("^") || vname.contains(":") {
                        show_alert(
                            &nv_window,
                            "Error",
                            "Vault name cannot contain '^' or ':' .",
                        );
                        return;
                    }
                    // Get master data
                    let (vtype, nonce_buf, base_cipher) = match read_master(&nv_window) {
                        Some(d) => {
                            nv_window.close();
                            d
                        }
                        None => {
                            nv_window.close();
                            return;
                        }
                    };
                    let comm_label = Rc::new(gtk4::Label::new(None));

                    // Decrypt master
                    if &vtype == b"d" {
                        // Default encryption
                        let obase_data =
                            decrypt_aes(aawindow.as_ref(), &base_cipher, nonce_buf, true);
                        if obase_data.is_none() {
                            return;
                        }
                        let sbase_data = String::from_utf8(obase_data.unwrap());
                        if sbase_data.is_err() {
                            show_alert(
                                aawindow.as_ref(),
                                "Error",
                                "Could not parse vault data as string.",
                            );
                            return;
                        }
                        let base_data = sbase_data.unwrap();
                        // Vault name validation check
                        for line in base_data.split("\n") {
                            if line.starts_with("^") || line.len() == 0 {
                                continue;
                            }
                            let vline = line.split_once(":");
                            if vline.is_none() {
                                show_alert(
                                    aawindow.as_ref(),
                                    "Error",
                                    "Failed to parse vault data. The vault may be broken.",
                                );
                                return;
                            }
                            if vline.unwrap().0 == vname.as_ref() {
                                show_alert(
                                    aawindow.as_ref(),
                                    "Alert",
                                    "You cannot use a same vault name.",
                                );
                                return;
                            }
                        }

                        let oadded_str = add_vault(
                            base_data,
                            Rc::clone(&vname).as_ref(),
                            nv_pass_box.text().to_string(),
                            aawindow.as_ref(),
                        );
                        if oadded_str.is_none() {
                            return;
                        }
                        let (added_master_raw, vault_data) = oadded_str.unwrap();
                        let added_master_str = Rc::new(added_master_raw);
                        // Save
                        let oadded_master = encrypt_aes(aawindow.as_ref(), &added_master_str);
                        if oadded_master.is_none() {
                            return;
                        }
                        let added_master = oadded_master.unwrap();
                        write_master(aawindow.as_ref(), b"d", added_master.0, added_master.1);
                        // Save after user edited data inside vault
                        let aaawindow = Rc::clone(&aawindow);
                        comm_label.connect_css_classes_notify(move |label| {
                            let encrypted_master =
                                match encrypt_aes(aaawindow.as_ref(), label.text().as_str()) {
                                    Some(s) => s,
                                    None => {
                                        show_alert(
                                            aaawindow.as_ref(),
                                            "Error",
                                            "Failed to encrypt master vault.",
                                        );
                                        return;
                                    }
                                };
                            write_master(
                                aaawindow.as_ref(),
                                b"d",
                                encrypted_master.0,
                                encrypted_master.1,
                            );
                        });
                        vault::ask_vault_password_and_open(
                            Rc::new(application),
                            Rc::clone(&added_master_str),
                            vault_data.split_once(":").unwrap().1.to_string(),
                            comm_label,
                        );
                    } else if &vtype == b"u" {
                        // Password encryption
                        // Ask password window
                        let pw_window = gtk4::Window::new();
                        pw_window.set_application(Some(&application));
                        pw_window.set_title(Some("Master password"));
                        pw_window.set_size_request(216, 84);
                        pw_window.set_resizable(false);

                        // Ask password grid
                        let pw_grid = gtk4::Grid::builder()
                            .margin_top(6)
                            .margin_bottom(6)
                            .margin_start(12)
                            .margin_end(12)
                            .row_spacing(8)
                            .column_spacing(8)
                            .build();
                        // Ask label
                        let pw_label =
                            gtk4::Label::new(Some("Enter password to open master vault."));
                        pw_grid.attach(&pw_label, 1, 1, 3, 1);
                        // Input box
                        let pw_box = gtk4::PasswordEntry::new();
                        pw_grid.attach(&pw_box, 1, 2, 2, 1);

                        let pw_ok_button = gtk4::Button::with_label("OK");
                        let aapprc = Rc::new(application);
                        let aaawindow = Rc::clone(&aawindow);
                        let commlabel_rc = Rc::clone(&comm_label);
                        let nv_pass_rc = Rc::clone(&nv_passbox_rc);
                        pw_ok_button.connect_clicked(clone!(
                            #[weak]
                            pw_window,
                            move |_| {
                                let user_key = Rc::new(hashify_sha256(&pw_box.text().to_string()));
                                let obase_data = decrypt_aes_with_key(
                                    &pw_window,
                                    &base_cipher,
                                    nonce_buf,
                                    user_key.as_ref(),
                                    false,
                                );
                                if obase_data.is_none() {
                                    show_alert(
                                        &pw_window,
                                        "Error",
                                        "Failed to decrypt master vault.",
                                    );
                                    return;
                                }
                                pw_window.close();
                                let sbase_data = String::from_utf8(obase_data.unwrap());
                                if sbase_data.is_err() {
                                    show_alert(
                                        aaawindow.as_ref(),
                                        "Error",
                                        "Could not parse vault data as string.",
                                    );
                                    return;
                                }
                                let base_data = sbase_data.unwrap();
                                // Vault name validation check
                                for line in base_data.split("\n") {
                                    if line.starts_with("^") || line.len() == 0 {
                                        continue;
                                    }
                                    let vline = line.split_once(":");
                                    if vline.is_none() {
                                        show_alert(
                                            aaawindow.as_ref(),
                                            "Error",
                                            "Failed to parse vault data. The vault may be broken.",
                                        );
                                        return;
                                    }
                                    if vline.unwrap().0 == vname.as_ref() {
                                        show_alert(
                                            aaawindow.as_ref(),
                                            "Alert",
                                            "You cannot use a same vault name.",
                                        );
                                        return;
                                    }
                                }
                                let (added_master_raw, vault_data) = match add_vault(
                                    base_data,
                                    vname.as_ref(),
                                    nv_pass_rc.text().to_string(),
                                    aaawindow.as_ref(),
                                ) {
                                    Some(added) => added,
                                    None => return,
                                };
                                let added_master_str = Rc::new(added_master_raw);
                                // Save
                                let added_master = match encrypt_aes_with_key(
                                    aaawindow.as_ref(),
                                    added_master_str.as_ref(),
                                    user_key.as_ref(),
                                ) {
                                    Some(v) => v,
                                    None => return,
                                };
                                write_master(
                                    aaawindow.as_ref(),
                                    b"u",
                                    added_master.0,
                                    added_master.1,
                                );
                                // Save after user edited data inside vault
                                let userkey_rc = Rc::clone(&user_key);
                                let aaaawindow = Rc::clone(&aaawindow);
                                comm_label.connect_css_classes_notify(move |label| {
                                    let encrypted_master = match encrypt_aes_with_key(
                                        aaaawindow.as_ref(),
                                        label.text().as_str(),
                                        userkey_rc.as_ref(),
                                    ) {
                                        Some(s) => s,
                                        None => {
                                            show_alert(
                                                aaaawindow.as_ref(),
                                                "Error",
                                                "Failed to encrypt master vault.",
                                            );
                                            return;
                                        }
                                    };
                                    write_master(
                                        aaaawindow.as_ref(),
                                        b"u",
                                        encrypted_master.0,
                                        encrypted_master.1,
                                    );
                                });
                                let encrypted_vault = match encrypt_aes_with_key(
                                    aaawindow.as_ref(),
                                    &vault_data,
                                    user_key.as_ref(),
                                ) {
                                    Some(s) => s,
                                    None => return,
                                };
                                vault::ask_vault_password_and_open(
                                    Rc::clone(&aapprc),
                                    added_master_str,
                                    format!(
                                        "{}{}",
                                        u8_to_hex(&encrypted_vault.0),
                                        u8_to_hex(&encrypted_vault.1)
                                    ),
                                    Rc::clone(&commlabel_rc),
                                );
                            }
                        ));
                        pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                        pw_window.set_child(Some(&pw_grid));
                        pw_window.set_modal(true);
                        pw_window.present();
                    } else {
                        show_alert(aawindow.as_ref(), "Error", "Could not parse vault data.");
                        return;
                    }
                }
            ));
            nv_grid.attach(&nv_ok_button, 4, 3, 1, 1);

            nv_window.set_child(Some(&nv_grid));
            nv_window.set_modal(true);
            nv_window.present();
        }
    ));
    grid.attach(&add_button, 1, 2, 1, 1);

    // Open vault button
    let open_button = gtk4::Button::new();
    open_button.set_size_request(120, 96);
    // Inside Open button
    let obbox = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    let obimg = gtk4::Image::new();
    obimg.set_size_request(48, 48);
    obimg.set_from_pixbuf(Some(&get_pixbuf_with_embedded_image(include_bytes!(
        "images/open.png"
    ))));
    obbox.append(&obimg);
    let oblabel = gtk4::Label::new(Some("Open vault"));
    obbox.append(&oblabel);
    open_button.set_child(Some(&obbox));
    // Inline function
    let owindow = Rc::clone(&window);
    open_button.connect_clicked(clone!(
        #[weak]
        application,
        move |_| {
            let selwindow = gtk4::Window::new();
            selwindow.set_application(Some(&application));
            selwindow.set_title(Some("Select vault..."));
            selwindow.set_size_request(320, 240);
            selwindow.set_modal(true);

            let selvbox = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(8)
                .margin_start(12)
                .margin_end(12)
                .build();

            let seltitle = gtk4::Label::new(Some("Select vault to open:"));
            seltitle.add_css_class("big");
            selvbox.append(&seltitle);

            // Show vault list widget family
            let selscroll = gtk4::ScrolledWindow::new();
            selscroll.set_size_request(180, 200);
            selscroll.set_hscrollbar_policy(gtk4::PolicyType::Never);
            let sellist = gtk4::ListBox::new();
            selscroll.set_child(Some(&sellist));
            selvbox.append(&selscroll);

            selwindow.set_child(Some(&selvbox));

            let omaster_data = read_master(&selwindow);
            if omaster_data.is_none() {
                return;
            }
            let (vtype, nonce_buf, base_cipher) = omaster_data.unwrap();
            let oapprc = Rc::new(application);
            // Decrypt master
            if &vtype == b"d" {
                // Default encryption
                let obase_data = decrypt_aes(&selwindow, &base_cipher, nonce_buf, false);
                if obase_data.is_none() {
                    show_alert(&selwindow, "Error", "Failed to decrypt master vault.");
                    return;
                }
                let rbase_string = String::from_utf8(obase_data.unwrap());
                if rbase_string.is_err() {
                    return;
                }
                let base_string = Rc::new(rbase_string.unwrap());
                // Save after user edited data inside vault
                let oowindow = Rc::clone(&owindow);
                let comm_label2 = Rc::new(gtk4::Label::new(None));
                comm_label2.connect_css_classes_notify(move |label| {
                    let encrypted_master =
                        match encrypt_aes(oowindow.as_ref(), label.text().as_str()) {
                            Some(s) => s,
                            None => {
                                show_alert(
                                    oowindow.as_ref(),
                                    "Error",
                                    "Failed to encrypt master vault.",
                                );
                                return;
                            }
                        };
                    write_master(
                        oowindow.as_ref(),
                        b"d",
                        encrypted_master.0,
                        encrypted_master.1,
                    );
                });

                for line in base_string.split("\n") {
                    if line.starts_with("^") {
                        continue;
                    }
                    if let Some((mvname, mvhex)) = line.split_once(":") {
                        let vlist_button = gtk4::Button::with_label(mvname);
                        let mvdata = mvhex.to_string();
                        let oapplrc = Rc::clone(&oapprc);
                        let commlabel_lrc = Rc::clone(&comm_label2);
                        let basestr_lrc = Rc::clone(&base_string);
                        vlist_button.connect_clicked(clone!(
                            #[weak]
                            selwindow,
                            move |_| {
                                selwindow.close();
                                vault::ask_vault_password_and_open(
                                    Rc::clone(&oapplrc),
                                    Rc::clone(&basestr_lrc),
                                    mvdata.clone(),
                                    Rc::clone(&commlabel_lrc),
                                );
                            }
                        ));
                        sellist.append(&vlist_button);
                    }
                }
                selwindow.present();
            } else if &vtype == b"u" {
                // Password encryption
                // Ask password window
                let pw_window = gtk4::Window::new();
                pw_window.set_application(Some(oapprc.as_ref()));
                pw_window.set_title(Some("Master password"));
                pw_window.set_size_request(216, 84);
                pw_window.set_resizable(false);

                // Ask password grid
                let pw_grid = gtk4::Grid::builder()
                    .margin_top(6)
                    .margin_bottom(6)
                    .margin_start(12)
                    .margin_end(12)
                    .row_spacing(8)
                    .column_spacing(8)
                    .build();

                // Ask label
                let pw_label = gtk4::Label::new(Some("Enter password to open master vault."));
                pw_grid.attach(&pw_label, 1, 1, 3, 1);
                // Input box
                let pw_boxr = gtk4::PasswordEntry::new();
                pw_grid.attach(&pw_boxr, 1, 2, 2, 1);
                let pw_box = Rc::new(pw_boxr);

                let pw_ok_button = gtk4::Button::with_label("OK");

                let oowindow = Rc::clone(&owindow);
                pw_ok_button.connect_clicked(clone!(
                    #[weak]
                    pw_window,
                    #[weak]
                    selwindow,
                    move |_| {
                        let obase_data = decrypt_aes_with_key(
                            &pw_window,
                            &base_cipher,
                            nonce_buf,
                            &hashify_sha256(&(pw_box.text().to_string() + MASTER_KEY_SALT)),
                            false,
                        );
                        if obase_data.is_none() {
                            show_alert(&pw_window, "Error", "Failed to decrypt master vault.");
                            return;
                        }
                        pw_window.close();
                        let rbase_string = String::from_utf8(obase_data.unwrap());
                        if rbase_string.is_err() {
                            return;
                        }
                        let base_string = Rc::new(rbase_string.unwrap());

                        // Save after user edited data inside vault
                        let ooowindow = Rc::clone(&oowindow);
                        let comm_label2 = Rc::new(gtk4::Label::new(None));
                        let opw_box = Rc::clone(&pw_box);
                        comm_label2.connect_css_classes_notify(move |label| {
                            let encrypted_master = match encrypt_aes_with_key(
                                ooowindow.as_ref(),
                                label.text().as_str(),
                                &hashify_sha256(&opw_box.text().to_string()),
                            ) {
                                Some(s) => s,
                                None => {
                                    show_alert(
                                        ooowindow.as_ref(),
                                        "Error",
                                        "Failed to encrypt master vault.",
                                    );
                                    return;
                                }
                            };
                            write_master(
                                ooowindow.as_ref(),
                                b"u",
                                encrypted_master.0,
                                encrypted_master.1,
                            );
                        });

                        for line in base_string.split("\n") {
                            if line.starts_with("^") {
                                continue;
                            }
                            if let Some((mvname, mvhex)) = line.split_once(":") {
                                let vlist_button = gtk4::Button::with_label(mvname);
                                let mvdata = mvhex.to_string();
                                let oapplrc = Rc::clone(&oapprc);
                                let commlabel_lrc = Rc::clone(&comm_label2);
                                let basestr_lrc = Rc::clone(&base_string);
                                vlist_button.connect_clicked(clone!(
                                    #[weak]
                                    selwindow,
                                    move |_| {
                                        selwindow.close();
                                        vault::ask_vault_password_and_open(
                                            Rc::clone(&oapplrc),
                                            Rc::clone(&basestr_lrc),
                                            mvdata.clone(),
                                            Rc::clone(&commlabel_lrc),
                                        );
                                    }
                                ));
                                sellist.append(&vlist_button);
                            }
                        }
                        selwindow.present();
                    }
                ));
                pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                pw_window.set_child(Some(&pw_grid));
                pw_window.present();
            } else {
                show_alert(&selwindow, "Error", "Could not parse vault data.");
                return;
            }
        }
    ));
    grid.attach(&open_button, 2, 2, 1, 1);

    // Delete vault button
    let delete_button = gtk4::Button::new();
    delete_button.set_size_request(120, 96);
    // Inside Delete button
    let dbbox = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    let dbimg = gtk4::Image::new();
    dbimg.set_size_request(48, 48);
    dbimg.set_from_pixbuf(Some(&get_pixbuf_with_embedded_image(include_bytes!(
        "images/delete.png"
    ))));
    dbbox.append(&dbimg);
    let dblabel = gtk4::Label::new(Some("Delete vault"));
    dbbox.append(&dblabel);
    delete_button.set_child(Some(&dbbox));
    // Inline function
    let dwindow = Rc::clone(&window);
    delete_button.connect_clicked(clone!(
        #[weak]
        application,
        move |_| {
            let selwindow = gtk4::Window::new();
            selwindow.set_application(Some(&application));
            selwindow.set_title(Some("Select vault..."));
            selwindow.set_size_request(320, 240);
            selwindow.set_modal(true);

            let selvbox = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
            selvbox.set_margin_start(12);
            selvbox.set_margin_end(12);

            let seltitle = gtk4::Label::new(Some("Select vault to delete:"));
            seltitle.add_css_class("big");
            selvbox.append(&seltitle);

            // Show vault list widget family
            let selscroll = gtk4::ScrolledWindow::new();
            selscroll.set_size_request(180, 200);
            selscroll.set_hscrollbar_policy(gtk4::PolicyType::Never);
            let sellist = gtk4::ListBox::new();
            selscroll.set_child(Some(&sellist));
            selvbox.append(&selscroll);
            selwindow.set_child(Some(&selvbox));

            let omaster_data = read_master(&selwindow);
            if omaster_data.is_none() {
                return;
            }
            let (vtype, nonce_buf, base_cipher) = omaster_data.unwrap();
            // Decrypt master
            if &vtype == b"d" {
                // Default encryption
                let obase_data = decrypt_aes(&selwindow, &base_cipher, nonce_buf, true);
                if obase_data.is_none() {
                    return;
                }
                let rbase_string = String::from_utf8(obase_data.unwrap());
                if rbase_string.is_err() {
                    show_alert(
                        &selwindow,
                        "Error",
                        "Failed to parse master vault to string.",
                    );
                    return;
                }

                let hidden_comm_label = gtk4::Label::new(None);
                let ddwindow = Rc::clone(&dwindow);
                hidden_comm_label.connect_css_classes_notify(clone!(
                    #[weak]
                    selwindow,
                    move |label| {
                        let newbase = label.text().to_string();
                        let obase_cipher = encrypt_aes(&selwindow, &newbase);
                        if obase_cipher.is_none() {
                            return;
                        }
                        let (nonced, based) = obase_cipher.unwrap();
                        write_master(&selwindow, b"d", nonced, based);
                        selwindow.close();
                        show_alert(
                            ddwindow.as_ref(),
                            "Vault deletion complete",
                            "Deletion command was issued for the selected vault.",
                        );
                    }
                ));
                for button in delete_button_vault_list(
                    Rc::new(rbase_string.unwrap()),
                    &application,
                    Rc::new(hidden_comm_label),
                ) {
                    sellist.append(&button);
                }
                selwindow.present();
            } else if &vtype == b"u" {
                // Password encryption
                // Ask password window
                let pw_window = gtk4::Window::new();
                pw_window.set_application(Some(&application));
                pw_window.set_title(Some("Master password"));
                pw_window.set_size_request(216, 84);
                pw_window.set_resizable(false);

                // Ask password grid
                let pw_grid = gtk4::Grid::builder()
                    .margin_top(6)
                    .margin_bottom(6)
                    .margin_start(12)
                    .margin_end(12)
                    .row_spacing(8)
                    .column_spacing(8)
                    .build();
                // Ask label
                let pw_label = gtk4::Label::new(Some("Enter password to open master vault."));
                pw_grid.attach(&pw_label, 1, 1, 3, 1);
                // Input box
                let pw_box = gtk4::PasswordEntry::new();
                pw_grid.attach(&pw_box, 1, 2, 2, 1);

                let pw_ok_button = gtk4::Button::with_label("OK");
                pw_ok_button.connect_clicked(clone!(
                    #[weak]
                    pw_box,
                    #[weak]
                    pw_window,
                    #[weak]
                    selwindow,
                    #[weak]
                    application,
                    move |_| {
                        let obase_data = decrypt_aes_with_key(
                            &pw_window,
                            &base_cipher,
                            nonce_buf,
                            &hashify_sha256(&(pw_box.text().to_string() + MASTER_KEY_SALT)),
                            false,
                        );
                        if obase_data.is_none() {
                            show_alert(&pw_window, "Error", "Failed to decrypt master vault.");
                            return;
                        }
                        pw_window.close();

                        let rbase_string = String::from_utf8(obase_data.unwrap());
                        if rbase_string.is_err() {
                            show_alert(
                                &selwindow,
                                "Error",
                                "Failed to parse master vault to string.",
                            );
                            return;
                        }

                        // A hidden label to communicate
                        let pw_base_hlabel = gtk4::Label::new(None);
                        pw_base_hlabel.connect_css_classes_notify(clone!(
                            #[weak]
                            selwindow,
                            move |label| {
                                let newbase = label.text().to_string();
                                let obase_cipher = encrypt_aes_with_key(
                                    &selwindow,
                                    &newbase,
                                    &hashify_sha256(&pw_box.text().to_string()),
                                );
                                if obase_cipher.is_none() {
                                    return;
                                }
                                let (nonced, based) = obase_cipher.unwrap();
                                write_master(&selwindow, b"u", nonced, based);
                                show_alert(
                                    &selwindow,
                                    "Vault deletion complete",
                                    "Deletion command was issued for the selected vault.",
                                );
                            }
                        ));

                        for button in delete_button_vault_list(
                            Rc::new(rbase_string.unwrap()),
                            &application,
                            Rc::new(pw_base_hlabel),
                        ) {
                            sellist.append(&button);
                        }
                        selwindow.present();
                    }
                ));
                pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                pw_window.set_child(Some(&pw_grid));
                pw_window.set_modal(true);
                pw_window.present();
            } else {
                show_alert(&selwindow, "Error", "Could not parse vault data.");
                return;
            }
        }
    ));
    grid.attach(&delete_button, 3, 2, 1, 1);

    window.set_child(Some(&grid));
    window.present();

    // Check if this is fresh
    // Get path
    let ovaultpath = get_vault_path();
    if ovaultpath.is_none() {
        show_alert(
            window.as_ref(),
            "Error",
            "Failed to detect the path to 'master.vbase'.",
        );
    }
    // Try to create new file, true if new
    let rbase_file = fs::File::create_new(ovaultpath.as_ref().unwrap());
    if rbase_file.is_ok() {
        // Fresh install, do some setup
        filebase_setup(
            &application,
            Rc::clone(&window),
            rbase_file.unwrap(),
            Rc::new(ovaultpath.unwrap()),
        );
    }
}

fn main() {
    println!(
        "\n==========\nTHIS IS A DEBUG VERSION, NOT INTENDED FOR RELEASE.\nREMOVE ALL 'eprintln!' BEFORE RELEASE.\nTHIS VERSION STILL CONTAINS BUGS. CONTACT DEVELOPER IF YOU SAW THIS.\n==========\n"
    );
    let application = gtk4::Application::new(
        Some("local.net.jp7654.filebase"),
        gtk4::gio::ApplicationFlags::HANDLES_OPEN,
    );
    application.connect_activate(open_main);
    application.run();
}
