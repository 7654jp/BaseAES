use std::ops::Deref;
use std::ops::DerefMut;

pub struct LabelWithInternalText {
    pub label: gtk4::Label,
    text: String,
}

impl LabelWithInternalText {
    pub fn new(label: gtk4::Label, text: String) -> Self {
        Self { label, text }
    }

    pub fn get_itext(&self) -> &String {
        &self.text
    }

    pub fn set_itext(&mut self, text: String) {
        self.text = text;
    }
}

impl Deref for LabelWithInternalText {
    type Target = gtk4::Label;

    fn deref(&self) -> &Self::Target {
        &self.label
    }
}

impl DerefMut for LabelWithInternalText {
    fn deref_mut(&mut self) -> &mut gtk4::Label {
        &mut self.label
    }
}

pub struct EntryWithInternalText {
    pub entry: gtk4::Entry,
    text: String,
}

impl EntryWithInternalText {
    pub fn new(entry: gtk4::Entry, text: String) -> Self {
        Self { entry, text }
    }

    pub fn get_itext(&self) -> &String {
        &self.text
    }

    pub fn set_itext(&mut self, text: String) {
        self.text = text;
    }

    pub fn set_itext_ref(&mut self, text: &String) {
        self.text = text.to_owned();
    }
}

impl Deref for EntryWithInternalText {
    type Target = gtk4::Entry;

    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

pub struct ButtonWithInternalText {
    pub button: gtk4::Button,
    text: String,
}

impl ButtonWithInternalText {
    pub fn new(button: gtk4::Button, text: String) -> Self {
        Self { button, text }
    }

    pub fn get_itext(&self) -> &String {
        &self.text
    }
}

impl Deref for ButtonWithInternalText {
    type Target = gtk4::Button;

    fn deref(&self) -> &Self::Target {
        &self.button
    }
}
