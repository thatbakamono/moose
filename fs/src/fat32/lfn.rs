use std::cmp::min;
use ucs2::Error;

/// Utility struct and method for converting a long file name (LFN) to a short file name (SFN) in the FAT (File Allocation Table) filesystem.
pub struct LongFileName {}

impl LongFileName {
    /// Converts a long file name (LFN) to a short file name (SFN) suitable for the FAT filesystem.
    ///
    /// # Parameters
    ///
    /// - `lfn`: The long file name (LFN) to convert.
    ///
    /// # Returns
    ///
    /// A `String` containing the converted short file name (SFN).
    pub fn convert_to_sfn(lfn: &str) -> String {
        let mut lossy = false;

        // Convert name to uppercase
        let mut lfn = lfn.to_ascii_uppercase();

        // Split the string into filename and extension
        let dot = lfn.rfind(".");

        let (mut filename, mut extension) = if let Some(dot_index) = dot {
            let (filename_part, mut extension_part) = lfn.split_at(dot_index);
            // Cut dot from extension
            (_, extension_part) = extension_part.split_at(1);

            // If extension is longer than 3 chars then cut it to fit in the 8+3 format
            if extension_part.len() > 3 {
                (extension_part, _) = extension_part.split_at(3);
            }

            (filename_part.to_string(), extension_part.to_string())
        } else {
            (lfn.clone(), "".to_string())
        };

        if filename.is_empty() && !extension.is_empty() {
            // Special case of dot at the first index
            // Need to set the lossy flag and set filename to everything after first character
            lossy = true;

            filename = String::from_utf8_lossy(&lfn.as_bytes()[1..]).to_string();
            extension = "".to_string();
        }

        // If filename is longer than 8 characters, then cut it and append `~1` at the end
        if filename.len() > 8 {
            lossy = true;
            filename = filename.split_at(7).0.to_string();
        }

        // If filename contains dot then remove it and set lossy flag
        if filename.contains(".") {
            lossy = true;
            filename = filename.replace(".", "");
        }

        // If something unusual happened, need to inform user that this is converted and not real
        // LFN, so add `~1` at the end of the filename
        if lossy {
            let filename_len = filename.len();

            if filename_len > 8 {
                filename.replace_range(6..8, "~1");
            } else if filename_len == 7 {
                filename.replace_range(6..7, "~");
                filename.push('1');
            } else {
                filename.push_str("~1");
            }
        }

        if extension.is_empty() {
            format!("{}{}", filename, extension)
        } else {
            format!("{}.{}", filename, extension)
        }
    }

    /// Converts a long file name (LFN) to a padded short file name (SFN) suitable for the FAT filesystem.
    ///
    /// # Parameters
    ///
    /// - `lfn`: The long file name (LFN) to convert.
    ///
    /// # Returns
    ///
    /// A `String` containing the padded short file name (SFN).
    pub fn padded_sfn(lfn: &str) -> String {
        let mut sfn = Self::convert_to_sfn(lfn);

        if sfn.len() != 11 {
            for i in sfn.len()..=11 {
                sfn.push(' ');
            }
        }

        sfn
    }
}

#[cfg(test)]
mod tests {
    use crate::fat32::lfn::LongFileName;

    #[test]
    fn test_normal_filename() {
        let lfn = "File.txt".to_string();
        let sfn = LongFileName::convert_to_sfn(&lfn);

        assert_eq!(sfn, "FILE.TXT");
    }

    #[test]
    fn test_long_filename() {
        let lfn = "foo.tar.gz".to_string();
        let sfn = LongFileName::convert_to_sfn(&lfn);

        assert_eq!(sfn, "FOOTAR~1.GZ");
    }

    #[test]
    fn test_dot_at_start() {
        let lfn = ".conf".to_string();
        let sfn = LongFileName::convert_to_sfn(&lfn);

        assert_eq!(sfn, "CONF~1");
    }

    #[test]
    fn test_long_filename_with_long_extension() {
        let lfn = "Asakura Otome.jpeg".to_string();
        let sfn = LongFileName::convert_to_sfn(&lfn);

        assert_eq!(sfn, "ASAKUR~1.JPE");
    }

    #[test]
    fn test_short_filename_without_extension() {
        let lfn = "Till".to_string();
        let sfn = LongFileName::convert_to_sfn(&lfn);

        assert_eq!(sfn, "TILL");
    }

    #[test]
    fn test_short_filename_with_extension() {
        let lfn = "Till.RA".to_string();
        let sfn = LongFileName::convert_to_sfn(&lfn);

        assert_eq!(sfn, "TILL.RA");
    }

    #[test]
    fn test_max_length_sfn() {
        // 8 + 3
        let lfn = "cobblest.one".to_string();
        let sfn = LongFileName::convert_to_sfn(&lfn);

        assert_eq!(sfn, "COBBLEST.ONE");
    }
}
