use ldap3::{LdapConn, LdapResult, SearchEntry, Scope};
use std::convert::TryFrom;
use std::fmt;
use std::mem::swap;
use serde::{Serialize, Deserialize};

/// Rsults produced by the crate
pub type Result<T> = ::std::result::Result<T, Error>;

/// A user as described by the various LDAP systems
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    /// UNSW zID
    pub zid: String,
    /// Self-chosen human-readable name
    pub name: String,
    /// Email address
    pub email: String,
    /// Login aliases for CSE
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Faculty or business unit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    /// Deparment or school
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// CSE group memberships
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cse_groups: Vec<String>,
}

impl User {
    /// Query a user from LDAP using their own credentials
    pub fn query(zid: impl AsRef<str>, password: impl AsRef<str>) -> Result<Self> {
        User::query_other(zid.as_ref(), password, zid.as_ref())
    }

    /// Query a user from LDAP using another user's credentials
    pub fn query_other(
        auth_zid: impl AsRef<str>,
        password: impl AsRef<str>,
        subject_zid: impl AsRef<str>,
    ) -> Result<Self> {

        let unsw = Conn::unsw(auth_zid, password)?;
        let query = format!("(&(cn={})(objectClass=user))", subject_zid.as_ref());
        let unsw_user = unsw
            .search::<UnswUser>(query)?
            .next()
            .ok_or(Error::InsufficientResults)
            .and_then(|user| user)?;

        let cse = Conn::cse()?;
        let query = format!("(&(cn={})(objectClass=account))", subject_zid.as_ref());
        let cse_user = cse
            .search::<CseUser>(query)?
            .next()
            .ok_or(Error::InsufficientResults)
            .and_then(|user| user)?;
        let query = format!("(&(member={})(objectClass=groupOfNames))", &cse_user.item.dn);
        let groups = cse
            .search::<CseGroup>(query)?
            .flat_map(|group| group.ok());

        let zid = unsw_user.name;
        let name = unsw_user.display_name;
        let email = unsw_user.mail;
        let aliases = cse_user.uids;
        let company = unsw_user.company;
        let department = unsw_user.department;
        let cse_groups = groups.map(|group| group.item.cn).collect();

        Ok(User { zid, name, email, aliases, company, department, cse_groups })
    }
}

struct Conn {
    base: &'static str,
    conn: LdapConn,
}

impl Conn {
    fn unsw(username: impl AsRef<str>, password: impl AsRef<str>) -> Result<Self> {
        let url = "ldaps://ad.unsw.edu.au/";
        let base = "OU=IDM,DC=ad,DC=unsw,DC=edu,DC=au";
        let conn = LdapConn::new(url)?;
        let username = format!("{}@ad.unsw.edu.au", username.as_ref());
        conn.simple_bind(&username, password.as_ref())?.success()?;
        Ok(Conn { base, conn })
    }

    fn cse() -> Result<Self> {
        let url = "ldaps://bandleader.cse.unsw.edu.au/";
        let base = "dc=cse,dc=unsw,dc=edu,dc=au";
        let conn = LdapConn::new(url)?;
        Ok(Conn { base, conn })
    }

    fn search<R: Response>(
        &self,
        filter: String,
    ) -> Result<impl Iterator<Item = Result<R>>> {
        let attrs = R::ATTRS.as_ref().iter().collect::<Vec<_>>();
        let (results, _) = self.conn
            .search(self.base, Scope::Subtree, filter.as_ref(), attrs)?
            .success()?;
        let results = results
            .into_iter()
            .map(SearchEntry::construct)
            .map(Deconstructor)
            .map(TryFrom::try_from);
        Ok(results)
    }
}

trait Response: TryFrom<Deconstructor, Error = Error> {
    const ATTRS: &'static [&'static str];
}

struct Deconstructor(SearchEntry);

impl Deconstructor {
    fn take_dn(&mut self) -> String {
        let mut removed = String::new();
        swap(&mut removed, &mut self.0.dn);
        removed
    }

    fn take_one(&mut self, name: &'static str) -> Result<String> {
        self.0.attrs
            .remove(name)
            .and_then(|attrs| attrs.into_iter().next())
            .ok_or(Error::AttributeMissing(name))
    }

    fn maybe_take_one(&mut self, name: &'static str) -> Option<String> {
        self.0.attrs
            .remove(name)
            .and_then(|attrs| attrs.into_iter().next())
    }

    fn take_all(&mut self, name: &'static str) -> Result<Vec<String>> {
        self.0.attrs
            .remove(name)
            .ok_or(Error::AttributeMissing(name))
    }
}

/// An item in an LDAP server
#[derive(Debug)]
struct LdapItem {
    /// Distinguished name
    dn: String,
    /// Common name
    cn: String,
}

impl Response for LdapItem {
    const ATTRS: &'static [&'static str] = &["cn", "dn"];
}

impl TryFrom<Deconstructor> for LdapItem {
    type Error = Error;

    fn try_from(mut entry: Deconstructor) -> Result<Self> {
        let dn = entry.take_dn();
        let cn = entry.take_one("cn")?;
        Ok(LdapItem { dn, cn })
    }
}

/// A group as recorded by the CSE LDAP server
#[derive(Debug)]
struct CseGroup {
    item: LdapItem,
}

impl Response for CseGroup {
    const ATTRS: &'static [&'static str] = &["cn", "dn"];
}

impl TryFrom<Deconstructor> for CseGroup {
    type Error = Error;

    fn try_from(entry: Deconstructor) -> Result<Self> {
        let item = LdapItem::try_from(entry)?;
        Ok(CseGroup { item })
    }
}

/// A user as recoded by the CSE LDAP server
#[derive(Debug)]
struct CseUser {
    item: LdapItem,
    uids: Vec<String>,
}

impl Response for CseUser {
    const ATTRS: &'static [&'static str] = &["cn", "dn", "uid"];
}

impl TryFrom<Deconstructor> for CseUser {
    type Error = Error;

    fn try_from(mut entry: Deconstructor) -> Result<Self> {
        let uids = entry.take_all("uid")?;
        let item = LdapItem::try_from(entry)?;
        Ok(CseUser { item, uids })
    }
}

/// A user as recoded by the UNSW LDAP server
#[derive(Debug)]
struct UnswUser {
    item: LdapItem,
    /// Faculty
    company: Option<String>,
    /// School
    department: Option<String>,
    /// Chosen human-readable name
    display_name: String,
    /// ZID
    name: String,
    /// Email address
    mail: String,
}

impl Response for UnswUser {
    const ATTRS: &'static [&'static str] = &[
        "cn", "dn",
        "company", "department",
        "displayName", "name",
        "mail",
    ];
}

impl TryFrom<Deconstructor> for UnswUser {
    type Error = Error;

    fn try_from(mut entry: Deconstructor) -> Result<Self> {
        let company = entry.maybe_take_one("company");
        let department = entry.maybe_take_one("department");
        let display_name = entry.take_one("displayName")?;
        let name = entry.take_one("name")?;
        let mail = entry.take_one("mail")?;
        let item = LdapItem::try_from(entry)?;
        Ok(UnswUser { item, company, department, display_name, name, mail })
    }
}

/// Errors produced by the interface
#[derive(Debug)]
pub enum Error {
    /// Not enough results were returned from an LDAP request
    InsufficientResults,
    /// The credentials used to authenticate were invalid
    InvalidCredentials,
    /// An attribute was missing from a search result
    AttributeMissing(&'static str),
    Ldap(LdapResult),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            InsufficientResults => write!(f, "No results were provided for the search"),
            InvalidCredentials => write!(f, "Invalid user credentials"),
            AttributeMissing(attr) => write!(f, "Response was missing attribute: {}", attr),
            Ldap(error) => write!(f, "{}", error),
            Io(error) => write!(f, "{}", error),
            Json(error) => write!(f, "{}", error),
        }
    }
}

impl std::error::Error for Error {}

impl From<LdapResult> for Error {
    fn from(error: LdapResult) -> Self {
        match error {
            LdapResult { rc: 49, .. } => Error::InvalidCredentials,
            error => Error::Ldap(error),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::Json(error)
    }
}
