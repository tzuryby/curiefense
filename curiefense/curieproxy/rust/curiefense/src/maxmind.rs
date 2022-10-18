use ipnet::IpNet;
use lazy_static::lazy_static;
use maxminddb::{
    geoip2::{Asn, City, Country},
    Reader,
};
use std::net::IpAddr;
#[cfg(not(test))]
use std::ops::Deref;

lazy_static! {
    // as they are lazy, these loads will not be triggered in test mode
    static ref ASN: Result<Reader<Vec<u8>>, maxminddb::MaxMindDBError> =
        Reader::open_readfile("/cf-config/current/config/maxmind/GeoLite2-ASN.mmdb");
    static ref COUNTRY: Result<Reader<Vec<u8>>, maxminddb::MaxMindDBError> =
        Reader::open_readfile("/cf-config/current/config/maxmind/GeoLite2-Country.mmdb");
    static ref CITY: Result<Reader<Vec<u8>>, maxminddb::MaxMindDBError> =
        Reader::open_readfile("/cf-config/current/config/maxmind/GeoIP2-City.mmdb").or_else(|_|
        Reader::open_readfile("/cf-config/current/config/maxmind/GeoLite2-City.mmdb"));
}

#[cfg(not(test))]
fn compute_network<T>(data: T, addr: IpAddr, prefix_len: usize) -> (T, Option<IpNet>) {
    let network = IpNet::new(addr, prefix_len as u8).ok();
    (data, network)
}

/// Retrieves the english name of the country associated with this IP
#[cfg(not(test))]
pub fn get_country(addr: IpAddr) -> Result<(Country<'static>, Option<IpNet>), String> {
    match COUNTRY.deref() {
        Err(rr) => Err(format!("could not read country db: {}", rr)),
        Ok(db) => match db.lookup_prefix(addr) {
            Ok((country, prefix_len)) => Ok(compute_network::<Country>(country, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_asn(addr: IpAddr) -> Result<(Asn<'static>, Option<IpNet>), String> {
    match ASN.deref() {
        Err(rr) => Err(format!("could not read ASN db: {}", rr)),
        Ok(db) => match db.lookup_prefix(addr) {
            Ok((asn, prefix_len)) => Ok(compute_network::<Asn>(asn, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(not(test))]
pub fn get_city(addr: IpAddr) -> Result<(City<'static>, Option<IpNet>), String> {
    match CITY.deref() {
        Err(rr) => Err(format!("could not read city db: {}", rr)),
        Ok(db) => match db.lookup_prefix(addr) {
            Ok((city, prefix_len)) => Ok(compute_network::<City>(city, addr, prefix_len)),
            Err(rr) => Err(format!("{}", rr)),
        },
    }
}

#[cfg(test)]
pub fn get_country(_addr: IpAddr) -> Result<(Country<'static>, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_asn(_addr: IpAddr) -> Result<(Asn<'static>, Option<IpNet>), String> {
    Err("TEST".into())
}

#[cfg(test)]
pub fn get_city(_addr: IpAddr) -> Result<(City<'static>, Option<IpNet>), String> {
    Err("TEST".into())
}
