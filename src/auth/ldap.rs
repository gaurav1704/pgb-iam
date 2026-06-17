/// LDAP authentication config.
pub struct LdapConfig {
    pub uri: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub search_base: String,
    pub search_filter: String,
}

/// Authenticate a user against LDAP.
pub async fn authenticate(
    config: &LdapConfig,
    user: &str,
    password: &str,
) -> anyhow::Result<()> {
    use ldap3::{LdapConnAsync, Scope, SearchEntry};
    use ldap3::drive;

    let (conn, mut ldap) = LdapConnAsync::new(&config.uri).await?;
    drive!(conn);

    ldap.simple_bind(&config.bind_dn, &config.bind_password).await?.success()?;

    let filter = config.search_filter.replace("$1", user);
    let (entries, _) = ldap
        .search(
            &config.search_base,
            Scope::Subtree,
            &filter,
            vec!["dn"],
        )
        .await?
        .success()?;

    if entries.is_empty() {
        anyhow::bail!("LDAP user not found: {}", user);
    }

    let user_dn = SearchEntry::construct(entries[0].clone()).dn;

    // Rebind as user to verify password
    let (user_conn, mut user_ldap) = LdapConnAsync::new(&config.uri).await?;
    drive!(user_conn);
    match user_ldap.simple_bind(&user_dn, password).await {
        Ok(r) => {
            r.success()?;
            Ok(())
        }
        Err(e) => anyhow::bail!("LDAP bind failed for {}: {:?}", user, e),
    }
}
