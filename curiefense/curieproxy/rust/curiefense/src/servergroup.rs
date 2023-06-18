use std::sync::Arc;

use crate::config::custom::{Site};
use crate::config::Config;
use crate::logs::Logs;

//todo update docs
/// finds the securitypolicy matching a given request, based on the configuration
/// there are cases where default values do not exist (even though the UI should prevent that)
///
/// note that the url is matched using the url-decoded path!
///
/// returns the matching security policy, along with the name and id of the selected host map
pub fn match_servergroup<'a>(
    cfg: &'a Config,
    logs: &mut Logs,
    selected_sergrp: Option<&str>,
) -> Arc<Site> {
    println!("## match_servergroup ##");
    println!("## selected_sergrp: {:?}", selected_sergrp);
    let site: Arc<Site> = match selected_sergrp {
        // None => get_hostmap()?,
        None => Arc::new(Site::default()),
        Some(sergrpid) => match cfg.servergroups_map.get(sergrpid) {
            Some(s) => Arc::new(s.clone()),
            None => {
                println!("## Can't find sergrp id {}", sergrpid);
                logs.error(|| format!("Can't find sergrp id {}", sergrpid));
                // get_hostmap()?
                Arc::new(Site::default())
            }
        },
    };
    println!("## site from selected_sergrp: {:?}", site);


    logs.debug(|| format!("Selected server group entry {}", site.id));
    site
}
