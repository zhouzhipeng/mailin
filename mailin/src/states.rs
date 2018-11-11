use std::fmt;
use std::io::Write;
use std::net::IpAddr;

#[derive(Debug)]
pub(crate) enum States {
    Invalid,
    Idle(Idle),
    Helo(Helo),
    IdleAuth(IdleAuth),
    HeloAuth(HeloAuth),
    Auth(Auth),
    Mail(Mail),
    Rcpt(Rcpt),
    Data(Data),
}

//------ Common functionality for states ---------------------------------------

pub(crate) trait State: Into<States> {
    fn get_ip(&self) -> IpAddr;

    fn require_auth(&self) -> bool {
        false
    }
}

//------ Data held in states ---------------------------------------------------

#[derive(Debug)]
pub(crate) struct Idle {
    ip: IpAddr,
}

impl State for Idle {
    fn get_ip(&self) -> IpAddr {
        self.ip
    }
}

#[derive(Debug)]
pub(crate) struct IdleAuth(Idle);

#[derive(Debug)]
pub(crate) struct Helo {
    pub ip: IpAddr,
    pub domain: String,
}

impl State for Helo {
    fn get_ip(&self) -> IpAddr {
        self.ip
    }
}

#[derive(Debug)]
pub(crate) struct HeloAuth(Helo);

#[derive(Debug)]
pub enum AuthMechanism {
    Plain,
}

#[derive(Debug)]
pub(crate) struct Auth {
    ip: IpAddr,
    domain: String,
    mechanism: AuthMechanism,
}

#[derive(Debug)]
pub struct Mail {
    pub ip: IpAddr,
    pub domain: String,
    pub reverse_path: String,
    pub is8bit: bool,
}

#[derive(Debug, Clone)]
pub struct Rcpt {
    pub ip: IpAddr,
    pub domain: String,
    pub reverse_path: String,
    pub is8bit: bool,
    pub forward_path: Vec<String>,
}

pub(crate) struct Data {
    ip: IpAddr,
    domain: String,
    writer: Box<Write>,
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Data{{ip: {:?}, domain: {:?}}}", self.ip, self.domain,)
    }
}

//------ Map State structs back to states --------------------------------------

impl From<Idle> for States {
    fn from(v: Idle) -> States {
        States::Idle(v)
    }
}

impl From<Helo> for States {
    fn from(v: Helo) -> States {
        States::Helo(v)
    }
}

impl From<IdleAuth> for States {
    fn from(v: IdleAuth) -> States {
        States::IdleAuth(v)
    }
}

impl From<HeloAuth> for States {
    fn from(v: HeloAuth) -> States {
        States::HeloAuth(v)
    }
}

impl From<Auth> for States {
    fn from(v: Auth) -> States {
        States::Auth(v)
    }
}

impl From<Mail> for States {
    fn from(v: Mail) -> States {
        States::Mail(v)
    }
}

impl From<Rcpt> for States {
    fn from(v: Rcpt) -> States {
        States::Rcpt(v)
    }
}

impl From<Data> for States {
    fn from(v: Data) -> States {
        States::Data(v)
    }
}
