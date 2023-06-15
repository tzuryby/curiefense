use serde_json::{from_value, Value};
use std::collections::HashMap;

use crate::config::raw::{RawCustom, RawSite};
use crate::logs::Logs;

#[derive(Debug, Clone)]
//server group object
pub struct CustomObject {
    pub content: Vec<ContentItem>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub enum ContentItem {
    Sites(Sites),
    // Add more variants for other object types
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Sites {
    id: String,
    name: String,
    description: String,
    items: std::collections::HashMap<String, Site>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    // description: String,
    // server_names: Vec<String>,
    // security_policy: String,
    // routing_profile: String,
    // proxy_template: String,
    // mobile_sdk: String,
    // ssl_certificate: String,
    pub challenge_cookie_domain: String, //new
}

impl Default for Site {
    fn default() -> Self {
        Self {
            id: ("siteid".to_string()),
            name: ("site name".to_string()),
            challenge_cookie_domain: "$host".to_string(),
        }
    }
}

impl Site {
    pub fn resolve(
        logs: &mut Logs,
        raw_sites: Vec<RawSite>,
    ) -> HashMap<String, Site> {
        // let mut servergroups: Vec<Site> = Vec::new();
        let mut sites_map: HashMap<String, Site> = HashMap::new();
        println!("&& server_groups_resolve");
        for raw_site in raw_sites {
            println!("&& server_groups_resolve in raw_site: {:?}", raw_site);

            let challenge_cookie_domain = raw_site.challenge_cookie_domain.unwrap_or_else(|| "$host".to_string());
            println!("&& server_groups_resolve challenge_cookie_domain: {}", challenge_cookie_domain);

            let site = Site {
                id: raw_site.id.clone(),
                name: raw_site.name.clone(),
                challenge_cookie_domain,
            };
            println!("&& server_groups_resolve sites_map.insert: {:?}", site);
            sites_map.insert(raw_site.id.clone(), site);
        }
        sites_map
    }
}

// impl CustomObject {
//     pub fn resolve(
//         logs: &mut Logs,
//         // rawCustom: RawCustom,
//         rawCustom: Vec<ContentItem>,
//     ) -> String {
//         "return test".to_string()
//     }
// }