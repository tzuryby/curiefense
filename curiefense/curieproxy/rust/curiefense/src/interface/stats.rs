use std::marker::PhantomData;

use crate::config::hostmap::SecurityPolicy;

pub struct BStageInit;
pub struct BStageSecpol;
pub struct BStageMapped;
pub struct BStageFlow;
pub struct BStageLimit;
pub struct BStageAcl;
pub struct BStageContentFilter;

#[derive(Debug, Default)]
pub struct Stats {
    pub revision: String,
    pub processing_stage: usize,
    // stage secpol
    pub acl_active: bool,
    pub content_filter_active: bool,
    // stage mapped
    pub globalfilters_total: usize,
    pub globalfilters_matched: usize,
    // stage flow
    pub flow_elements: usize,
    pub flow_checked: usize,
    pub flow_matched: usize,
    // stage limit
    pub limit_total: usize,
    pub limit_matched: usize,
    // stage content filter
    pub rules_total: usize,
    pub rules_matches: usize,
}

// the builder uses a phantom data structure to make sure we did not forget to update the stats from a previous stage
#[derive(Debug)]
pub struct StatsCollect<A> {
    stats: Stats,
    phantom: PhantomData<A>,
}

impl StatsCollect<BStageInit> {
    pub fn new(revision: String) -> Self {
        StatsCollect {
            stats: Stats {
                revision,
                processing_stage: 0,
                acl_active: false,
                content_filter_active: false,
                globalfilters_total: 0,
                globalfilters_matched: 0,
                flow_elements: 0,
                flow_checked: 0,
                flow_matched: 0,
                limit_total: 0,
                limit_matched: 0,
                rules_total: 0,
                rules_matches: 0,
            },
            phantom: PhantomData,
        }
    }

    pub fn secpol(self, pol: &SecurityPolicy) -> StatsCollect<BStageSecpol> {
        let mut stats = self.stats;
        stats.processing_stage = 1;
        stats.acl_active = pol.acl_active;
        stats.content_filter_active = pol.content_filter_active;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }

    pub fn content_filter_only(self) -> StatsCollect<BStageAcl> {
        let mut stats = self.stats;
        stats.processing_stage = 5;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }
}

impl StatsCollect<BStageSecpol> {
    pub fn mapped(self, globalfilters_total: usize, globalfilters_matched: usize) -> StatsCollect<BStageMapped> {
        let mut stats = self.stats;
        stats.processing_stage = 2;
        stats.globalfilters_total = globalfilters_total;
        stats.globalfilters_matched = globalfilters_matched;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }
}

impl StatsCollect<BStageMapped> {
    pub fn mapped_stage_build(self) -> Stats {
        self.stats
    }

    pub fn no_flow(self, flow_elements: usize) -> StatsCollect<BStageFlow> {
        let mut stats = self.stats;
        stats.processing_stage = 3;
        stats.flow_elements = flow_elements;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }

    pub fn flow(self, flow_elements: usize, flow_checked: usize, flow_matched: usize) -> StatsCollect<BStageFlow> {
        let mut stats = self.stats;
        stats.processing_stage = 3;
        stats.flow_elements = flow_elements;
        stats.flow_checked = flow_checked;
        stats.flow_matched = flow_matched;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }
}

impl StatsCollect<BStageFlow> {
    pub fn flow_stage_build(self) -> Stats {
        self.stats
    }

    pub fn no_limit(self) -> StatsCollect<BStageLimit> {
        let mut stats = self.stats;
        stats.processing_stage = 4;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }

    pub fn limit(self, total: usize, matched: usize) -> StatsCollect<BStageLimit> {
        let mut stats = self.stats;
        stats.processing_stage = 4;
        stats.limit_total = total;
        stats.limit_matched = matched;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }
}

impl StatsCollect<BStageLimit> {
    pub fn limit_stage_build(self) -> Stats {
        self.stats
    }

    pub fn acl(self) -> StatsCollect<BStageAcl> {
        let mut stats = self.stats;
        stats.processing_stage = 5;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }
}

impl StatsCollect<BStageAcl> {
    pub fn acl_stage_build(self) -> Stats {
        self.stats
    }

    pub fn no_content_filter(self) -> StatsCollect<BStageContentFilter> {
        let mut stats = self.stats;
        stats.processing_stage = 6;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }

    pub fn cf_no_match(self, total: usize) -> StatsCollect<BStageContentFilter> {
        let mut stats = self.stats;
        stats.processing_stage = 6;
        stats.rules_total = total;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }

    pub fn cf_matches(self, total: usize, matches: usize) -> StatsCollect<BStageContentFilter> {
        let mut stats = self.stats;
        stats.processing_stage = 6;
        stats.rules_total = total;
        stats.rules_matches = matches;
        StatsCollect {
            stats,
            phantom: PhantomData,
        }
    }
}

impl StatsCollect<BStageContentFilter> {
    pub fn cf_stage_build(self) -> Stats {
        self.stats
    }
}
