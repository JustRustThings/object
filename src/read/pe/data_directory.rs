use core::slice;

use crate::read::{ReadError, ReadRef, Result};
use crate::{pe, LittleEndian as LE};

use super::{ExportTable, ImportTable, RelocationBlockIterator, ResourceDirectory, SectionTable};

/// The table of data directories in a PE file.
#[derive(Debug, Clone, Copy)]
pub struct DataDirectories<'data> {
    entries: &'data [pe::ImageDataDirectory],
}

impl<'data> DataDirectories<'data> {
    /// Parse the data directory table.
    ///
    /// `data` must be the remaining optional data following the
    /// [optional header](pe::ImageOptionalHeader64).  `number` must be from the
    /// [`number_of_rva_and_sizes`](pe::ImageOptionalHeader64::number_of_rva_and_sizes)
    /// field of the optional header.
    pub fn parse(data: &'data [u8], number: u32) -> Result<Self> {
        let entries = data
            .read_slice_at(0, number as usize)
            .read_error("Invalid PE number of RVA and sizes")?;
        Ok(DataDirectories { entries })
    }

    /// The number of data directories.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterator over the data directories.
    pub fn iter(&self) -> slice::Iter<'data, pe::ImageDataDirectory> {
        self.entries.iter()
    }

    /// Iterator which gives the directories as well as their index (one of the IMAGE_DIRECTORY_ENTRY_* constants).
    pub fn enumerate(&self) -> core::iter::Enumerate<slice::Iter<'data, pe::ImageDataDirectory>> {
        self.entries.iter().enumerate()
    }

    /// Returns the data directory at the given index.
    ///
    /// Index should be one of the `IMAGE_DIRECTORY_ENTRY_*` constants.
    ///
    /// Returns `None` if the index is larger than the table size,
    /// or if the entry at the index has a zero virtual address.
    pub fn get(&self, index: usize) -> Option<&'data pe::ImageDataDirectory> {
        self.entries
            .get(index)
            .filter(|d| d.virtual_address.get(LE) != 0)
    }

    /// Returns the unparsed export directory.
    ///
    /// `data` must be the entire file data.
    pub fn export_directory<R: ReadRef<'data>>(
        &self,
        data: R,
        sections: &SectionTable<'data>,
    ) -> Result<Option<&'data pe::ImageExportDirectory>> {
        let data_dir = match self.get(pe::IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(data_dir) => data_dir,
            None => return Ok(None),
        };
        let export_data = data_dir.data(data, sections)?;
        ExportTable::parse_directory(export_data).map(Some)
    }

    /// Returns the partially parsed export directory.
    ///
    /// `data` must be the entire file data.
    pub fn export_table<R: ReadRef<'data>>(
        &self,
        data: R,
        sections: &SectionTable<'data>,
    ) -> Result<Option<ExportTable<'data>>> {
        let data_dir = match self.get(pe::IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(data_dir) => data_dir,
            None => return Ok(None),
        };
        let export_va = data_dir.virtual_address.get(LE);
        let export_data = data_dir.data(data, sections)?;
        ExportTable::parse(export_data, export_va).map(Some)
    }

    /// Returns the partially parsed import directory.
    ///
    /// `data` must be the entire file data.
    pub fn import_table<R: ReadRef<'data>>(
        &self,
        data: R,
        sections: &SectionTable<'data>,
    ) -> Result<Option<ImportTable<'data, R>>> {
        let data_dir = match self.get(pe::IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(data_dir) => data_dir,
            None => return Ok(None),
        };
        let import_va = data_dir.virtual_address.get(LE);
        Ok(Some(ImportTable::new(data, sections.clone(), import_va)))
    }

    /// Returns the blocks in the base relocation directory.
    ///
    /// `data` must be the entire file data.
    pub fn relocation_blocks<R: ReadRef<'data>>(
        &self,
        data: R,
        sections: &SectionTable<'data>,
    ) -> Result<Option<RelocationBlockIterator<'data>>> {
        let data_dir = match self.get(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            Some(data_dir) => data_dir,
            None => return Ok(None),
        };
        let reloc_data = data_dir.data(data, sections)?;
        Ok(Some(RelocationBlockIterator::new(reloc_data)))
    }

    /// Returns the resource directory.
    ///
    /// `data` must be the entire file data.
    pub fn resource_directory<R: ReadRef<'data>>(
        &self,
        data: R,
        sections: &SectionTable<'data>,
    ) -> Result<Option<ResourceDirectory<'data>>> {
        let data_dir = match self.get(pe::IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            Some(data_dir) => data_dir,
            None => return Ok(None),
        };
        let rsrc_data = data_dir.data(data, sections)?;
        Ok(Some(ResourceDirectory::new(rsrc_data)))
    }

    /// Compute the maximum file offset used by data directories.
    ///
    /// This will usually match the end of file, unless the PE file has a
    /// [data overlay](https://security.stackexchange.com/questions/77336/how-is-the-file-overlay-read-by-an-exe-virus)
    ///
    /// Note that the "security" directory (that contains a file signature) is ignored because it is considered an exception to the concept of a data overlay
    pub fn max_directory_file_offset(
        &self,
        file_size_if_known: Option<u64>,
        section_table: &'data SectionTable,
    ) -> Option<u64> {
        let mut max = None;

        for (dir_index, directory) in self.enumerate() {
            if dir_index == pe::IMAGE_DIRECTORY_ENTRY_SECURITY {
                continue;
            }

            let rva = directory.virtual_address.get(LE);
            let section_for_dir = match section_table.section_at(file_size_if_known, rva) {
                None => continue,
                Some(sec) => sec,
            };

            match rva
                .checked_sub(section_for_dir.virtual_address.get(LE))
                .and_then(|value| value.checked_sub(section_for_dir.pointer_to_raw_data.get(LE)))
                .and_then(|file_offset| {
                    (file_offset as u64).checked_add(directory.size.get(LE) as u64)
                }) {
                None => {
                    // This cannot happen, we're suming two u32 into a u64
                    continue;
                }
                Some(end_of_directory) => {
                    if let Some(total_size) = file_size_if_known {
                        if end_of_directory > total_size {
                            // We can safely ignore directories that report a bogus size
                            continue;
                        }
                    }

                    if end_of_directory > max.unwrap_or(0) {
                        max = Some(end_of_directory);
                    }
                }
            }
        }
        max
    }
}

impl pe::ImageDataDirectory {
    /// Return the virtual address range of this directory entry.
    ///
    /// For correctly formatted PE files, this range does not overlap sections.
    pub fn address_range(&self) -> (u32, u32) {
        (self.virtual_address.get(LE), self.size.get(LE))
    }

    /// Return the file offset range of this directory entry.
    ///
    /// For correctly formatted PE files, this range does not overlap sections.
    pub fn file_range<'data>(&self, sections: &SectionTable<'data>) -> Result<(u32, u32)> {
        let start_section = sections
            .section_at(None, self.virtual_address.get(LE))
            .ok_or(crate::read::Error(
                "This directory does not point to a valid section",
            ))?;

        let section_file_offset = start_section.pointer_to_raw_data.get(LE);
        let section_va = start_section.virtual_address.get(LE);
        let start = self
            .virtual_address
            .get(LE)
            .checked_sub(section_va)
            .and_then(|a| a.checked_add(section_file_offset))
            .ok_or(crate::read::Error("Invalid directory addresses"))?;
        let end = start
            .checked_add(self.size.get(LE))
            .ok_or(crate::read::Error("Invalid directory addresses"))?;

        Ok((start, end))
    }

    /// Get the data referenced by this directory entry.
    ///
    /// This function has some limitations:
    /// - It requires that the data is contained in a single section.
    /// - It uses the size field of the directory entry, which is
    /// not desirable for all data directories.
    /// - It uses the `virtual_address` of the directory entry as an address,
    /// which is not valid for `IMAGE_DIRECTORY_ENTRY_SECURITY`.
    pub fn data<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        sections: &SectionTable<'data>,
    ) -> Result<&'data [u8]> {
        sections
            .pe_data_at(data, self.virtual_address.get(LE))
            .read_error("Invalid data dir virtual address")?
            .get(..self.size.get(LE) as usize)
            .read_error("Invalid data dir size")
    }
}
