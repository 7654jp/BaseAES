/*
 *   BaseAES, a simple filesystem-like vault system with strong encryption.
 *   Copyright (C) 2026  7654jp
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::collections::BTreeMap;
use std::ops::Deref;
use std::ops::DerefMut;
use std::rc::Rc;

use gtk4::prelude::WidgetExt;

pub const VDATA_INDEX_APPEND: i16 = -32000;
pub type Cipher = ([u8; 12], Vec<u8>);

pub struct ItemContainer<T> {
    value: T,
}

impl<T> ItemContainer<T> {
    pub fn new(value: T) -> Self {
        ItemContainer { value }
    }

    pub fn get(&self) -> &T {
        &self.value
    }

    pub fn set(&mut self, value: T) {
        self.value = value;
    }
}

pub struct RawPixbuf {
    pub data: Vec<u8>,
    pub has_alpha: bool,
    pub width: i32,
    pub height: i32,
}

impl RawPixbuf {
    pub fn new(data: Vec<u8>, has_alpha: bool, width: i32, height: i32) -> Self {
        Self {
            data,
            has_alpha,
            width,
            height,
        }
    }
}

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

    pub fn with_label(label: &str, text: String) -> Self {
        Self {
            button: gtk4::Button::with_label(label),
            text,
        }
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

#[derive(Clone)]
pub enum IDCSImageType {
    Png,
    Jpeg,
}

impl IDCSImageType {
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "image/png" => Some(IDCSImageType::Png),
            "image/jpeg" => Some(IDCSImageType::Jpeg),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct ImgDecodeItem {
    pub imgtype: IDCSImageType,
    pub data: Vec<u8>,
}

impl ImgDecodeItem {
    pub fn new(imgtype: IDCSImageType, data: Vec<u8>) -> Self {
        Self { imgtype, data }
    }
}

pub struct ImgDecodingController {
    pub queue: BTreeMap<u32, ImgDecodeItem>,
    pub image_provider: BTreeMap<u32, Rc<gtk4::Picture>>,
    pub is_processing: bool,
    cindex: u32,
}

impl ImgDecodingController {
    pub fn new() -> Self {
        Self {
            queue: BTreeMap::new(),
            image_provider: BTreeMap::new(),
            is_processing: false,
            cindex: 0,
        }
    }

    pub fn request_decode(
        &mut self,
        img_type: IDCSImageType,
        img_data: Vec<u8>,
        iviewer: Rc<gtk4::Picture>,
    ) {
        let curr_index = self.cindex;
        iviewer.add_css_class(&curr_index.to_string());
        self.queue
            .insert(curr_index, ImgDecodeItem::new(img_type, img_data));
        self.image_provider.insert(curr_index, iviewer);
        if self.cindex == u32::MAX {
            self.cindex = 0;
        } else {
            self.cindex += 1;
        }
    }
}
