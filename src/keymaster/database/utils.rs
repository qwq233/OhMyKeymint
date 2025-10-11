use anyhow::{Context, Result};
use rusqlite::{types::FromSql, Row, Rows};

use crate::keymaster::error::KsError;

// Takes Rows as returned by a query call on prepared statement.
// Extracts exactly one row with the `row_extractor` and fails if more
// rows are available.
// If no row was found, `None` is passed to the `row_extractor`.
// This allows the row extractor to decide on an error condition or
// a different default behavior.
pub fn with_rows_extract_one<'a, T, F>(rows: &mut Rows<'a>, row_extractor: F) -> Result<T>
where
    F: FnOnce(Option<&Row<'a>>) -> Result<T>,
{
    let result = row_extractor(
        rows.next()
            .context("with_rows_extract_one: Failed to unpack row.")?,
    );

    rows.next()
        .context("In with_rows_extract_one: Failed to unpack unexpected row.")?
        .map_or_else(|| Ok(()), |_| Err(KsError::sys()))
        .context("In with_rows_extract_one: Unexpected row.")?;

    result
}

pub fn with_rows_extract_all<'a, F>(rows: &mut Rows<'a>, mut row_extractor: F) -> Result<()>
where
    F: FnMut(&Row<'a>) -> Result<()>,
{
    loop {
        match rows
            .next()
            .context("In with_rows_extract_all: Failed to unpack row")?
        {
            Some(row) => {
                row_extractor(row).context("In with_rows_extract_all.")?;
            }
            None => break Ok(()),
        }
    }
}

/// This struct is defined to postpone converting rusqlite column value to the
/// appropriate key parameter value until we know the corresponding tag value.
/// Wraps the column index and a rusqlite row.
pub struct SqlField<'a>(usize, &'a Row<'a>);

impl<'a> SqlField<'a> {
    /// Creates a new SqlField with the given index and row.
    pub fn new(index: usize, row: &'a Row<'a>) -> Self {
        Self(index, row)
    }
    /// Returns the column value from the row, when we know the expected type.
    pub fn get<T: FromSql>(&self) -> rusqlite::Result<T> {
        self.1.get(self.0)
    }
}

/// This macro implements two types to aid in the implementation of a type safe metadata
/// store. The first is a collection of metadata and the second is the entry in that
/// collection. The caller has to provide the infrastructure to load and store the
/// the collection or individual entries in a SQLite database. The idea is that once
/// the infrastructure for a metadata collection is in place all it takes to add another
/// field is make a new entry in the list of variants (see details below).
///
/// # Usage
/// ```
/// impl_metadata!{
///     /// This is the name of the collection.
///     #[derive(Debug, Default)]
///     pub struct CollectionName;
///     /// This is the name of the Entry type followed by a list of variants, accessor function
///     /// names, and types.
///     #[derive(Debug, Eq, PartialEq)]
///     pub enum EntryName {
///         /// An enum variant with an accessor function name.
///         VariantA(u32) with accessor get_variant_a,
///         /// A second variant. `MyType` must implement rusqlite::types::ToSql and FromSql.
///         VariantB(MyType) with accessor get_variant_b,
///         //  --- ADD NEW META DATA FIELDS HERE ---
///         // For backwards compatibility add new entries only to
///         // end of this list and above this comment.
///     };
/// }
/// ```
///
/// expands to:
///
/// ```
/// pub enum EntryName {
///     VariantA(u32),
///     VariantB(MyType),
/// }
///
/// impl EntryName {}
///     /// Returns a numeric variant id that can be used for persistent storage.
///     fn db_tag(&self) -> i64 {...}
///     /// Helper function that constructs a new `EntryName` given a variant identifier
///     /// and a to-be-extracted `SqlFiled`
///     fn new_from_sql(db_tag: i64, data: &SqlField) -> Result<Self> {...}
/// }
///
/// impl ToSql for EntryName {...}
///
/// pub struct CollectionName {
///     data: std::collections::HashMap<i64, EntryName>,
/// }
///
/// impl CollectionName {
///     /// Create a new collection of meta data.
///     pub fn new() -> Self {...}
///     /// Add a new entry to this collection. Replaces existing entries of the
///     /// same variant unconditionally.
///     pub fn add(&mut self, e: EntryName) {...}
///     /// Type safe accessor function for the defined fields.
///     pub fn get_variant_a() -> Option<u32> {...}
///     pub fn get_variant_b() -> Option<MyType> {...}
/// }
///
/// let mut collection = CollectionName::new();
/// collection.add(EntryName::VariantA(3));
/// let three: u32 = collection.get_variant_a().unwrap()
/// ```
///
/// The caller of this macro must implement the actual database queries to load and store
/// either a whole collection of metadata or individual fields. For example by associating
/// with the given type:
/// ```
/// impl CollectionName {
///     fn load(tx: &Transaction) -> Result<Self> {...}
/// }
/// ```
#[macro_export]
macro_rules! impl_metadata {
    // These two macros assign incrementing numeric ids to each field which are used as
    // database tags.
    (@gen_consts {} {$($n:ident $nid:tt,)*} {$($count:tt)*}) => {
        $(
            // This allows us to reuse the variant name for these constants. The constants
            // are private so that this exception does not spoil the public interface.
            #[allow(non_upper_case_globals)]
            const $n: i64 = $nid;
        )*
    };
    (@gen_consts {$first:ident $(,$tail:ident)*} {$($out:tt)*} {$($count:tt)*}) => {
        impl_metadata!(@gen_consts {$($tail),*} {$($out)* $first ($($count)*),} {$($count)* + 1});
    };
    (
        $(#[$nmeta:meta])*
        $nvis:vis struct $name:ident;
        $(#[$emeta:meta])*
        $evis:vis enum $entry:ident {
            $($(#[$imeta:meta])* $vname:ident($t:ty) with accessor $func:ident),* $(,)?
        };
    ) => {
        $(#[$emeta])*
        $evis enum $entry {
            $(
                $(#[$imeta])*
                $vname($t),
            )*
        }

        impl $entry {
            fn db_tag(&self) -> i64 {
                match self {
                    $(Self::$vname(_) => $name::$vname,)*
                }
            }

            fn new_from_sql(db_tag: i64, data: &SqlField) -> anyhow::Result<Self> {
                match db_tag {
                    $(
                        $name::$vname => {
                            Ok($entry::$vname(
                                data.get()
                                .with_context(|| format!(
                                    "In {}::new_from_sql: Unable to get {}.",
                                    stringify!($entry),
                                    stringify!($vname)
                                ))?
                            ))
                        },
                    )*
                    _ => Err(anyhow!(format!(
                        "In {}::new_from_sql: unknown db tag {}.",
                        stringify!($entry), db_tag
                    ))),
                }
            }
        }

        impl rusqlite::types::ToSql for $entry {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                match self {
                    $($entry::$vname(v) => v.to_sql(),)*
                }
            }
        }

        $(#[$nmeta])*
        $nvis struct $name {
            data: std::collections::HashMap<i64, $entry>,
        }

        impl $name {
            /// Create a new instance of $name
            pub fn new() -> Self {
                Self{data: std::collections::HashMap::new()}
            }

            impl_metadata!{@gen_consts {$($vname),*} {} {0}}

            /// Add a new instance of $entry to this collection of metadata.
            pub fn add(&mut self, entry: $entry) {
                self.data.insert(entry.db_tag(), entry);
            }
            $(
                /// If the variant $vname is set, returns the wrapped value or None otherwise.
                pub fn $func(&self) -> Option<&$t> {
                    if let Some($entry::$vname(v)) = self.data.get(&Self::$vname) {
                        Some(v)
                    } else {
                        None
                    }
                }
            )*
        }
    };
}
