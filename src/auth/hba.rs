use std::net::IpAddr;

/// HBA authentication methods.
#[allow(dead_code)]
pub enum HbaAuth {
    Trust,
    Password,
    ScramSha256,
    Cert,
    Pam,
    Ldap,
    Reject,
}

/// An HBA rule entry.
#[allow(dead_code)]
pub struct HbaRule {
    pub conn_type: String,
    pub database: Vec<String>,
    pub user: Vec<String>,
    pub address: Option<String>,
    pub auth: HbaAuth,
}

/// Match a rule against connection parameters.
#[allow(dead_code)]
pub fn match_rule(rule: &HbaRule, user: &str, database: &str, addr: Option<IpAddr>, tls: bool) -> bool {
    match rule.conn_type.as_str() {
        "local" => { if addr.is_some() { return false; } }
        "host" => { if addr.is_none() { return false; } }
        "hostssl" => { if addr.is_none() || !tls { return false; } }
        "hostnossl" => { if addr.is_none() || tls { return false; } }
        _ => return false,
    }

    if !rule.database.iter().any(|d| d == "all" || d == database || (d == "sameuser" && database == user)) {
        return false;
    }
    if !rule.user.iter().any(|u| u == "all" || u == user) {
        return false;
    }
    if let Some(ref addr_str) = rule.address {
        let client_ip = match addr {
            Some(ip) => ip,
            None => return false,
        };
        if let Ok(net) = addr_str.parse::<ipnetwork::IpNetwork>() {
            if !net.contains(client_ip) {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}
