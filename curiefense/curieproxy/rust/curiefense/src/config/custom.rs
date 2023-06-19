use std::collections::HashMap;

use crate::config::raw::RawSite;
use crate::logs::Logs;

/// Contains objects for the custom.json file

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    // pub mobile_sdk: String,
    pub challenge_cookie_domain: String,
}

impl Default for Site {
    fn default() -> Self {
        Self {
            id: ("siteid".to_string()),
            name: ("site name".to_string()),
            // mobile_sdk: ("mobile sdk".to_string()),
            challenge_cookie_domain: "$host".to_string(),
        }
    }
}

impl Site {
    pub fn resolve(logs: &mut Logs, raw_sites: Vec<RawSite>) -> HashMap<String, Site> {
        let mut sites_map: HashMap<String, Site> = HashMap::new();
        println!("&& server_groups_resolve");
        for raw_site in raw_sites {
            println!("&& server_groups_resolve in raw_site: {:?}", raw_site);

            let challenge_cookie_domain = raw_site.challenge_cookie_domain.unwrap_or_else(|| "$host".to_string());
            println!(
                "&& server_groups_resolve challenge_cookie_domain: {}",
                challenge_cookie_domain
            );

            let site = Site {
                id: raw_site.id.clone(),
                name: raw_site.name.clone(),
                // mobile_sdk: raw_site.mobile_sdk.clone(),
                challenge_cookie_domain,
            };
            println!("&& server_groups_resolve sites_map.insert: {:?}", site);
            sites_map.insert(raw_site.id.clone(), site);
        }
        sites_map
    }
}
